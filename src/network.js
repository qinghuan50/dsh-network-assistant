import net from 'node:net';
import tls from 'node:tls';
import { Agent, Dispatcher, request, buildConnector, getGlobalDispatcher, setGlobalDispatcher } from 'undici';
import { bypasses, errorCode, fail, isLoopback } from './config.js';

const noFallback=(e)=>/CERT|TLS_CERT|SSL_CERT|INVALID_ARG|INVALID_URL/.test(e?.code||'');
// TUN paths and remote proxy nodes can need more than five seconds for a cold TLS
// handshake. Keep transport deadlines separate from the caller's overall request limit.
const TCP_TIMEOUT_MS=10000;
const TLS_TIMEOUT_MS=30000;
const PROXY_CONNECT_TIMEOUT_MS=15000;
const bare=(h)=>h.replace(/^\[|\]$/g,'');
const authority=(host,port)=>`${net.isIP(bare(host))===6?'['+bare(host)+']':bare(host)}:${port}`;
function ready(socket,event,ms){return new Promise((resolve,reject)=>{const timer=setTimeout(()=>done(Object.assign(new Error('CONNECT_TIMEOUT'),{code:'CONNECT_TIMEOUT'})),ms);const done=(e)=>{clearTimeout(timer);socket.off(event,onReady);socket.off('error',onError);if(e){socket.destroy();reject(e);}else resolve(socket);};const onReady=()=>done(),onError=(e)=>done(e);socket.once(event,onReady);socket.once('error',onError);});}
async function dial(host,port,secure,ms,socket){
  const s=secure?tls.connect({host:bare(host),...(socket?{socket}:{port}),...(net.isIP(bare(host))?{}:{servername:bare(host)})}):net.connect({host:bare(host),port});
  return ready(s,secure?'secureConnect':'connect',ms);
}
/** CONNECT is completed before any caller HTTP body is accepted. No application request is replayed. */
async function tunnel(proxy,host,port,ms){
  const p=new URL(proxy.url),s=await dial(p.hostname,Number(p.port)||(p.protocol==='https:'?443:80),p.protocol==='https:',ms);
  try{return await new Promise((resolve,reject)=>{
    let bytes=Buffer.alloc(0),settled=false;
    const timer=setTimeout(()=>done(Object.assign(new Error('PROXY_TIMEOUT'),{code:'PROXY_TIMEOUT'})),ms);
    const done=(e)=>{if(settled)return;settled=true;clearTimeout(timer);s.off('data',onData);s.off('error',onError);s.off('end',onEnd);if(e){s.destroy();reject(e);}else resolve(s);};
    const onError=(e)=>done(e),onEnd=()=>done(Object.assign(new Error('PROXY_BAD_REPLY'),{code:'PROXY_BAD_REPLY'}));
    const onData=(chunk)=>{bytes=Buffer.concat([bytes,chunk]);if(bytes.length>32768)return done(Object.assign(new Error('PROXY_BAD_REPLY'),{code:'PROXY_BAD_REPLY'}));const end=bytes.indexOf('\r\n\r\n');if(end<0)return;const status=Number(/^HTTP\/1\.[01] (\d{3})/.exec(bytes.toString('latin1'))?.[1]);if(status!==200)return done(Object.assign(new Error(`PROXY_CONNECT_${status||0}`),{code:`PROXY_CONNECT_${status||0}`}));s.pause();const rest=bytes.subarray(end+4);if(rest.length)s.unshift(rest);done();};
    s.on('data',onData);s.once('error',onError);s.once('end',onEnd);
    const auth=proxy.auth?`Proxy-Authorization: Basic ${Buffer.from(proxy.auth).toString('base64')}\r\n`:'';
    s.write(`CONNECT ${authority(host,port)} HTTP/1.1\r\nHost: ${authority(host,port)}\r\n${auth}\r\n`);
  });}catch(e){s.destroy();throw e;}
}

/** Outbound sockets and Node fetch share one policy. Every configuration creates fresh pools. */
export class Network extends Dispatcher {
  constructor({record=()=>{},managed=()=>new Set()}={}){
    super();this.record=record;this.managed=managed;this.baseline=getGlobalDispatcher();this.config={mode:'inherit',paused:false,routes:{},bypass:''};this.proxy={url:'',auth:'',reachable:false};this.agents=new Map();this.retiring=new Set();this.oldAgents=new Set();this.preferred=new Map();this.generation=0;this.closed=false;this.installed=false;
    this.nativeConnect=buildConnector({timeout:TLS_TIMEOUT_MS});this.connections=new Map();
  }
  install(){if(this.installed&&getGlobalDispatcher()!==this)fail('DISPATCHER_CONFLICT');if(!this.installed){this.baseline=getGlobalDispatcher();setGlobalDispatcher(this);this.installed=true;}}
  uninstall(){if(this.installed&&getGlobalDispatcher()===this){setGlobalDispatcher(this.baseline);this.installed=false;}}
  configure(config,proxy){
    const fingerprint=JSON.stringify([config.mode,config.source,config.paused,config.routes,config.bypass,config.tlsCompatOrigins,proxy]);
    this.config=config;this.proxy=proxy;
    if(fingerprint===this.fingerprint)return;this.fingerprint=fingerprint;this.generation++;this.preferred.clear();this.connections.clear();
    for(const agent of this.agents.values()){this.oldAgents.add(agent);const closing=agent.close().catch(()=>{}).finally(()=>{this.retiring.delete(closing);this.oldAgents.delete(agent);});this.retiring.add(closing);}this.agents.clear();
  }
  /** Unmanaged model URLs inherit the host; tool gateway requests opt into the default policy. */
  policy(url,tool=false){
    if(isLoopback(url.hostname)||bypasses(url.hostname,this.config.bypass))return 'direct';
    if(this.config.paused)return 'inherit';
    if(!tool&&!this.managed().has(url.origin)&&!Object.hasOwn(this.config.routes,url.origin))return 'inherit';
    const override=this.config.routes[url.origin];const mode=override&&override!=='inherit'?override:this.config.mode||'inherit';
    // With no proxy source, preserve the host transport unless this model origin
    // explicitly opted into the compatibility connector. Raw tool tunnels do not
    // gain an implicit direct policy from a model's TLS preference.
    if(mode==='smart'&&!this.proxy.url&&!tool)return this.tlsCompatibility(url)?'direct':'inherit';
    // Following a source must actually use its configured proxy. Node's baseline
    // dispatcher does not automatically read the macOS/Windows system settings.
    return mode==='inherit'?(this.proxy.url?'proxy':!tool&&this.tlsCompatibility(url)?'direct':'inherit'):mode;
  }
  tlsCompatibility(url){return url.protocol==='https:'&&this.config.tlsCompatOrigins?.includes(url.origin)===true;}
  /** Describe the policy actually used for this origin, including a missing fallback. */
  routeStatus(url){
    const override=this.config.routes[url.origin];
    const requestedMode=override&&override!=='inherit'?override:this.config.mode||'inherit';
    const effectiveMode=this.policy(url);
    const managed=this.managed().has(url.origin)||Object.hasOwn(this.config.routes,url.origin);
    const issue=effectiveMode==='proxy'&&!this.proxy.url?'PROXY_NOT_CONFIGURED':managed&&!this.config.paused&&requestedMode==='smart'&&effectiveMode==='inherit'&&!this.proxy.url?'SMART_WITHOUT_FALLBACK':'';
    return {requestedMode,effectiveMode,issue};
  }
  /** Use undici's standard TLS/SNI/ALPN handling, including TLS over a CONNECT socket. */
  nativeSocket(url,httpSocket){return new Promise((resolve,reject)=>this.nativeConnect({hostname:bare(url.hostname),host:url.host,protocol:url.protocol,port:url.port||(url.protocol==='https:'?443:80),...(httpSocket?{httpSocket}:{})},(error,socket)=>error?reject(error):resolve(socket)));}
  /**
   * The TLS server may serve this hostname's valid certificate without SNI. Opted-in
   * origins may try that handshake after a reset, before any HTTP headers/body exist.
   * Trust-chain and original-hostname verification stay mandatory; certificates,
   * HTTP failures and partial application requests never trigger this retry.
   */
  async directSocket(url){
    try{return {socket:await this.nativeSocket(url),tls:url.protocol==='https:'?'standard':''};}
    catch(error){if(!this.tlsCompatibility(url)||error.code!=='ECONNRESET')throw error;}
    const hostname=bare(url.hostname);
    const socket=tls.connect({host:hostname,port:Number(url.port)||443,servername:undefined,rejectUnauthorized:true,ALPNProtocols:['http/1.1'],checkServerIdentity:(_name,cert)=>tls.checkServerIdentity(hostname,cert)});
    // Keep an error listener during the promise hand-off to undici, as its native
    // connector does; undici adds its own request error handling after hand-off.
    socket.on('error',()=>{});
    socket.setNoDelay(true);socket.setKeepAlive(true,60000);
    return {socket:await ready(socket,'secureConnect',TLS_TIMEOUT_MS),tls:'compat'};
  }
  async socket(url,{raw=false,tool=false,mode,proxy=this.proxy}={}){
    const policy=mode||this.policy(url,tool),host=url.hostname,port=Number(url.port)||(url.protocol==='https:'?443:80);
    if(policy==='inherit'&&!tool)fail('RAW_BASELINE_UNAVAILABLE');
    // A gateway cannot delegate an opaque TCP socket to a dispatcher. In inherit mode it
    // reports that limitation instead of silently treating an unknown baseline as direct.
    if(policy==='inherit')fail('TERMINAL_USE_EXPLICIT_MODE');
    // Smart mode is always direct first. Only pre-request connection failures may
    // use the configured proxy; an application POST is never replayed to switch paths.
    const order=policy==='direct'||policy==='smart'&&!proxy.url?['direct']:policy==='proxy'?['proxy']:['direct','proxy'];
    let last;const generation=this.generation;
    for(const via of order){
      if(via==='proxy'&&!proxy.url){last=Object.assign(new Error('PROXY_NOT_CONFIGURED'),{code:'PROXY_NOT_CONFIGURED'});continue;}
      let socket,tlsMode='';
      try{
        if(via==='proxy')socket=await tunnel(proxy,host,port,PROXY_CONNECT_TIMEOUT_MS);
        else if(raw)socket=await dial(host,port,false,TCP_TIMEOUT_MS);
        else{const direct=await this.directSocket(url);socket=direct.socket;tlsMode=direct.tls;}
        if(via==='proxy'&&!raw&&url.protocol==='https:')socket=await this.nativeSocket(url,socket);
        if(generation===this.generation){this.preferred.set(url.origin,via);this.connections.delete(url.origin);this.connections.set(url.origin,{at:Date.now(),via,tls:tlsMode||(via==='proxy'&&!raw&&url.protocol==='https:'?'standard':'')});if(this.connections.size>500)this.connections.delete(this.connections.keys().next().value);}
        return {socket,via};
      }catch(e){socket?.destroy();last=e;if(noFallback(e)||policy!=='smart')throw e;}
    }
    throw last||new Error('CONNECT_FAILED');
  }
  agent(url,mode,tool=false){
    const key=[this.generation,url.origin,mode,tool].join('|');if(this.agents.has(key))return this.agents.get(key);
    const proxy={...this.proxy};const direct=(mode==='direct'||mode==='smart'&&!proxy.url)&&!this.tlsCompatibility(url);
    const agent=new Agent({connections:8,pipelining:1,connect:direct?{timeout:TLS_TIMEOUT_MS}:(opts,callback)=>{this.socket(new URL(opts.origin||`${opts.protocol}//${authority(opts.hostname,opts.port|| (opts.protocol==='https:'?443:80))}`),{mode,tool,proxy}).then(({socket})=>callback(null,socket),e=>callback(e,null));}});
    this.agents.set(key,agent);return agent;
  }
  dispatch(options,handler){return this.send(options,handler,false);}
  send(options,handler,tool){
    if(this.closed){queueMicrotask(()=>handler.onError(new Error('PLUGIN_DISPOSED')));return false;}
    let url;try{url=new URL(String(options.path||'/'),String(options.origin));}catch(e){queueMicrotask(()=>handler.onError(e));return false;}
    const mode=this.policy(url,tool),start=Date.now();let status=0,done=false;
    const finish=(error)=>{if(done)return;done=true;this.record({at:Date.now(),origin:url.origin,method:options.method||'GET',kind:/\/models\/?$/.test(url.pathname)?'catalog':'request',mode,via:mode==='inherit'?'host':this.preferred.get(url.origin)||mode,status,code:error?errorCode(error):'',elapsedMs:Date.now()-start});};
    const wrapped=new Proxy(handler,{get:(target,key)=>{const value=target[key];if(typeof value!=='function')return value;return(...args)=>{if(key==='onHeaders')status=args[0];if(key==='onResponseStart')status=args[1];if(key==='onError'||key==='onResponseError')finish(args.at(-1));if(key==='onComplete'||key==='onResponseEnd')finish();return value.apply(target,args);};}});
    return (mode==='inherit'?this.baseline:this.agent(url,mode,tool)).dispatch(options,wrapped);
  }
  toolDispatcher(){return {dispatch:(opts,handler)=>this.send(opts,handler,true)};}
  /** Bounded explicit diagnostics; redirects are returned, never followed with an API key. */
  async collect(url,{method='GET',headers={},body,signal,tool=false,limit=4*1024*1024,timeout=45000,dispatcher}={}){
    const result=await request(url,{method,headers,body,signal:AbortSignal.any([...(signal?[signal]:[]),AbortSignal.timeout(timeout)]),dispatcher:dispatcher||(tool?this.toolDispatcher():this),headersTimeout:timeout,bodyTimeout:timeout,maxRedirections:0});
    const chunks=[];let size=0;try{for await(const chunk of result.body){size+=chunk.length;if(size>limit)fail('REPLY_TOO_LARGE');chunks.push(chunk);}return {status:result.statusCode,body:Buffer.concat(chunks),headers:result.headers};}finally{result.body.destroy();}
  }
  async dispose(){
    this.closed=true;if(this.installed&&getGlobalDispatcher()===this)setGlobalDispatcher(this.baseline);this.installed=false;
    await Promise.allSettled([...this.agents.values(),...this.oldAgents].map(a=>a.destroy()));this.agents.clear();this.oldAgents.clear();this.connections.clear();
  }
}
