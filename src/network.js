import net from 'node:net';
import tls from 'node:tls';
import { Agent, Dispatcher, request, getGlobalDispatcher, setGlobalDispatcher } from 'undici';
import { bypasses, errorCode, fail, isLoopback } from './config.js';

const noFallback=(e)=>/CERT|TLS_CERT|SSL_CERT|INVALID_ARG|INVALID_URL/.test(e?.code||'');
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
  }
  install(){if(this.installed&&getGlobalDispatcher()!==this)fail('DISPATCHER_CONFLICT');if(!this.installed){this.baseline=getGlobalDispatcher();setGlobalDispatcher(this);this.installed=true;}}
  configure(config,proxy){
    const fingerprint=JSON.stringify([config.mode,config.paused,config.routes,config.bypass,proxy]);
    this.config=config;this.proxy=proxy;
    if(fingerprint===this.fingerprint)return;this.fingerprint=fingerprint;this.generation++;this.preferred.clear();
    for(const agent of this.agents.values()){this.oldAgents.add(agent);const closing=agent.close().catch(()=>{}).finally(()=>{this.retiring.delete(closing);this.oldAgents.delete(agent);});this.retiring.add(closing);}this.agents.clear();
  }
  /** Unmanaged model URLs inherit the host; tool gateway requests opt into the default policy. */
  policy(url,tool=false){
    if(isLoopback(url.hostname)||bypasses(url.hostname,this.config.bypass))return 'direct';
    if(this.config.paused)return 'inherit';
    if(!tool&&!this.managed().has(url.origin)&&!Object.hasOwn(this.config.routes,url.origin))return 'inherit';
    return this.config.routes[url.origin]||this.config.mode||'inherit';
  }
  async socket(url,{raw=false,tool=false,mode,proxy=this.proxy}={}){
    const policy=mode||this.policy(url,tool),host=url.hostname,port=Number(url.port)||(url.protocol==='https:'?443:80);
    if(policy==='inherit'&&!tool)fail('RAW_BASELINE_UNAVAILABLE');
    // A gateway cannot delegate an opaque TCP socket to a dispatcher. In inherit mode it
    // reports that limitation instead of silently treating an unknown baseline as direct.
    if(policy==='inherit')fail('TERMINAL_USE_EXPLICIT_MODE');
    const remembered=this.preferred.get(url.origin);
    const order=policy==='direct'?['direct']:policy==='proxy'?['proxy']:(tool||remembered==='proxy')&&proxy.reachable?['proxy','direct']:['direct','proxy'];
    let last;const generation=this.generation;
    for(const via of order){
      if(via==='proxy'&&!proxy.url){last=Object.assign(new Error('PROXY_NOT_CONFIGURED'),{code:'PROXY_NOT_CONFIGURED'});continue;}
      let socket;
      try{
        socket=via==='proxy'?await tunnel(proxy,host,port,5000):await dial(host,port,false,3000);
        if(!raw&&url.protocol==='https:')socket=await dial(host,port,true,5000,socket);
        if(generation===this.generation)this.preferred.set(url.origin,via);
        return {socket,via};
      }catch(e){socket?.destroy();last=e;if(noFallback(e)||policy!=='smart')throw e;}
    }
    throw last||new Error('CONNECT_FAILED');
  }
  agent(url,mode,tool=false){
    const key=[this.generation,url.origin,mode,tool].join('|');if(this.agents.has(key))return this.agents.get(key);
    const proxy={...this.proxy};const agent=new Agent({connections:8,pipelining:1,connect:(opts,callback)=>{this.socket(new URL(opts.origin||`${opts.protocol}//${authority(opts.hostname,opts.port|| (opts.protocol==='https:'?443:80))}`),{mode,tool,proxy}).then(({socket})=>callback(null,socket),e=>callback(e,null));}});
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
  async collect(url,{method='GET',headers={},body,signal,tool=false,limit=4*1024*1024,timeout=15000,dispatcher}={}){
    const result=await request(url,{method,headers,body,signal:AbortSignal.any([...(signal?[signal]:[]),AbortSignal.timeout(timeout)]),dispatcher:dispatcher||(tool?this.toolDispatcher():this),headersTimeout:timeout,bodyTimeout:timeout,maxRedirections:0});
    const chunks=[];let size=0;try{for await(const chunk of result.body){size+=chunk.length;if(size>limit)fail('REPLY_TOO_LARGE');chunks.push(chunk);}return {status:result.statusCode,body:Buffer.concat(chunks),headers:result.headers};}finally{result.body.destroy();}
  }
  async dispose(){
    this.closed=true;if(this.installed&&getGlobalDispatcher()===this)setGlobalDispatcher(this.baseline);this.installed=false;
    await Promise.allSettled([...this.agents.values(),...this.oldAgents].map(a=>a.destroy()));this.agents.clear();this.oldAgents.clear();
  }
}
