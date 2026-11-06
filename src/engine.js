import path from 'node:path';
import os from 'node:os';
import { randomBytes, createHash } from 'node:crypto';
import { DEFAULTS, NS, normalize, endpoint, APIS, MODES, fail, providerId, credentialRef, modelsFrom, listingURL, errorCode, isLoopback } from './config.js';
import { Network } from './network.js';
import { systemProxy, candidates, tcpProbe } from './detect.js';
import { TerminalGateway } from './terminal.js';
import { RuleManager, GITHUB_HOSTS } from './rules.js';
import { CoreManager } from './core.js';
import { controllerSecretFromFile } from './rule-discovery.js';

/** Host-only coordinator. Secrets never enter persisted configuration or RPC state projections. */
export class NetworkEngine {
  constructor(ctx,initial={},options={}){
    this.ctx=ctx;this.initial=initial;this.closed=false;this.queue=Promise.resolve();this.events=[];this.lastResults=new Map();this.publishError='';this.health={url:'',reachable:false,source:'none',reason:''};
    const profile=String(ctx.profileContext?.name||'default');
    this.dir=options.dir||path.join(process.env.DSH_HOME||path.join(os.homedir(),'.dsh'),'network-assistant',createHash('sha256').update(profile).digest('hex').slice(0,12));
    this.network=new Network({record:e=>{this.events.unshift(e);this.events=this.events.slice(0,150);},managed:()=>new Set(this.routes().map(c=>{try{return endpoint(c.baseURL).origin;}catch{return '';}}).filter(Boolean))});
    this.gateway=new TerminalGateway(this.network,{dir:path.join(this.dir,'sessions'),record:e=>{this.events.unshift(e);this.events=this.events.slice(0,150);}});
    this.rules=new RuleManager({dir:path.join(this.dir,'rules'),config:()=>this.value(),secret:async()=>await this.secret('NA_CONTROLLER')||await controllerSecretFromFile(this.value().effectivePath)});
    this.core=new CoreManager({dir:path.join(this.dir,'core'),secret:()=>this.secret('NA_CORE_SUBSCRIPTION'),onChange:()=>this.closed?undefined:this.refreshNetwork()});
    this.installGlobal=options.installGlobal!==false;
  }
  section(){
    const section=this.ctx.settings.describe({redactSecrets:false}).find(x=>x.ns===NS);if(section)return section;
    const value={...DEFAULTS};for(const key of Object.keys(DEFAULTS)){const input=this.initial[key];if(input===undefined)continue;try{value[key]=typeof input?.get==='function'?input.get():input;}catch{}}
    return {value,revision:0};
  }
  value(){return normalize(this.section().value||{});}
  serial(fn){const job=this.queue.catch(()=>{}).then(()=>{if(this.closed)fail('PLUGIN_DISPOSED');return fn();});this.queue=job;return job;}
  async secret(ref){return (await this.ctx.credentials.resolve(ref).catch(()=>null))?.value||'';}
  async configured(ref){return (await this.ctx.credentials.describe(ref).catch(()=>null))?.configured===true;}
  checkRevision(revision){if(revision!==this.section().revision)fail('CONFIG_CONFLICT');}
  async write(ops,revision){this.checkRevision(revision);await this.ctx.settings.mutate(NS,ops,revision);}
  /** Restore credential changes if their associated settings mutation does not commit. */
  async withCredentials(changes,commit){
    const previous=await Promise.all(changes.map(async([ref])=>[ref,(await this.ctx.credentials.resolve(ref))?.value]));const changed=[];
    try{for(const [ref,value]of changes){if(value===undefined)await this.ctx.credentials.unset(ref);else await this.ctx.credentials.set(ref,value);changed.push(ref);}return await commit();}
    catch(error){for(const [ref,value]of previous.reverse())if(changed.includes(ref)){try{if(value===undefined)await this.ctx.credentials.unset(ref);else await this.ctx.credentials.set(ref,value);}catch{fail('CREDENTIAL_ROLLBACK_FAILED');}}throw error;}
  }
  /** Read exact configurable-provider settings paths; do not infer namespaces from package names. */
  nativeRoutes(){
    let entries;try{entries=this.ctx.llm.listConfigurableProviders();}catch{return [];}
    const sections=this.ctx.settings.describe({redactSecrets:false});
    return entries.flatMap(entry=>{
      if(entry.provider?.startsWith('net-assist-'))return [];
      const section=sections.find(s=>s.ns===entry.settingsNs);let profile=section?.value;for(const p of entry.settingsPath||[])profile=profile?.[p];
      let baseURL=profile?.baseURL||entry.baseURL||(profile?entry.defaultBaseURL:'')||'';try{if(baseURL)endpoint(baseURL);}catch{baseURL='';}
      return [{id:entry.provider,name:profile?.displayName||entry.displayName||entry.provider,baseURL,api:profile?.api||entry.api||'',models:(profile?.models||[]).map(x=>({id:x.id,name:x.name||x.id})),managed:false,entry,profile}];
    });
  }
  routes(){return [...this.nativeRoutes(),...this.value().channels.map(c=>({...c,id:providerId(c.id),channelId:c.id,managed:true}))];}
  async refreshNetwork(){
    const value=this.value();let info;
    if(value.source==='system')info=await systemProxy();else info={url:value.source==='core'?this.core.proxyURL:value.proxyUrl,source:value.source,reason:''};
    if(this.closed||JSON.stringify(value)!==JSON.stringify(this.value()))return;
    const reachable=!!info.url&&await tcpProbe(info.url);
    const auth=value.source==='manual'?await this.secret('NA_PROXY_AUTH'):'';
    if(this.closed||JSON.stringify(value)!==JSON.stringify(this.value()))return;
    this.health={...info,reachable,checkedAt:Date.now()};
    this.network.configure(value,{url:info.url||'',reachable,auth});
    const explicit=mode=>mode==='direct'||mode==='proxy';
    const needsRouting=!value.paused&&(explicit(value.mode)||!!info.url||Object.values(value.routes).some(explicit)||value.tlsCompatOrigins.length>0);
    if(this.installGlobal){try{if(needsRouting)this.network.install();else this.network.uninstall();}catch(e){this.health.routingError=errorCode(e);throw e;}}
    if(value.terminalEnabled&&!this.gateway.server)await this.gateway.start();
    // Existing terminal windows may still reference this gateway. Keep it alive until plugin
    // disposal; disabling affects newly opened sessions and never leaves old windows a dead port.
  }
  async initialize(){
    if(!this.timer){this.timer=setInterval(()=>{if(!this.closed)this.serial(()=>this.refreshNetwork()).catch(()=>{});},8000);this.timer.unref?.();}
    await this.refreshNetwork();try{await this.publish();}catch(e){this.publishError=errorCode(e);}
  }
  async state(){
    const value=this.value();const routes=await Promise.all(this.routes().map(async c=>({
      id:c.id,channelId:c.channelId||'',name:c.name,baseURL:c.baseURL,api:c.api,models:c.managed||c.models?.length?c.models:(await this.ctx.llm.listModels(c.id).catch(()=>[])).slice(0,5000).map(m=>({id:m.id,name:m.name||m.id})),managed:c.managed,
      origin:c.baseURL?endpoint(c.baseURL).origin:'',mode:c.baseURL?value.routes[endpoint(c.baseURL).origin]||'inherit':'inherit',
      routing:c.baseURL?this.network.routeStatus(endpoint(c.baseURL)):{requestedMode:'inherit',effectiveMode:'inherit',issue:''},
      tlsCompatibility:!!c.baseURL&&value.tlsCompatOrigins.includes(endpoint(c.baseURL).origin),
      connection:c.baseURL?this.network.connections.get(endpoint(c.baseURL).origin)||null:null,
      keyConfigured:c.managed?await this.configured(credentialRef(c.channelId)):undefined,
      catalog:this.lastResults.get(c.id)||null,
      chat:this.lastChats?.get(c.id)||null,
      recent:this.events.find(e=>c.baseURL&&e.origin===endpoint(c.baseURL).origin&&e.kind!=='catalog')||null,
    })));
    const visibleRoutes=routes.filter(c=>c.managed||c.baseURL||c.models.length);
    return {revision:this.section().revision,generatedAt:Date.now(),config:value,health:this.health,routes:visibleRoutes,events:this.events,platform:process.platform,capabilities:{chatTest:typeof this.ctx.llm.prepareCall==='function'},core:this.core.status(),rules:await this.rules.status(),secrets:{proxy:await this.configured('NA_PROXY_AUTH'),controller:await this.configured('NA_CONTROLLER'),coreSubscription:await this.configured('NA_CORE_SUBSCRIPTION')},terminal:{enabled:value.terminalEnabled,running:!!this.gateway.server,port:this.gateway.port||0,activeSessionScripts:this.gateway.sessions.length,automaticCommands:false,automaticReason:'HOST_EXECUTION_ADAPTER_REQUIRED',sshSupported:false},publishError:this.publishError,dispatcherActive:this.network.installed};
  }
  async saveConfig(draft,revision,secrets={}){return this.serial(async()=>{
    const allowed=['mode','paused','showSidebar','source','proxyUrl','bypass','terminalEnabled','controllerURL','effectivePath','scriptPath','ruleClient','corePath'];
    if(!draft||typeof draft!=='object'||Object.keys(draft).some(k=>!allowed.includes(k)))fail('INVALID_CONFIG');
    const next=normalize({...this.value(),...draft}),current=this.value();this.checkRevision(revision);
    const managed=await this.rules.status();if(managed.managed&&['controllerURL','effectivePath','scriptPath','ruleClient'].some(k=>next[k]!==current[k]))fail('UNDO_RULES_BEFORE_CONFIG_CHANGE');
    if(this.core.running&&(next.corePath!==current.corePath||secrets.coreSubscription))fail('CORE_STOP_BEFORE_EDIT');
    const changes=[];
    for(const [key,ref]of Object.entries({proxyAuth:'NA_PROXY_AUTH',controller:'NA_CONTROLLER',coreSubscription:'NA_CORE_SUBSCRIPTION'})){
      const value=secrets[key];if(value===undefined||value==='')continue;if(typeof value!=='string'||value.length>8192||/[\r\n\0]/.test(value))fail('INVALID_SECRET');
      if(key==='coreSubscription'){let u;try{u=new URL(value);}catch{fail('INVALID_SUBSCRIPTION');}if(!['http:','https:'].includes(u.protocol)||u.username||u.password||u.hash)fail('INVALID_SUBSCRIPTION');}
      changes.push([ref,value]);
    }
    await this.withCredentials(changes,()=>this.write(Object.keys(draft).map(key=>({op:'set',path:[key],value:next[key]})),revision));await this.refreshNetwork();return this.state();
  });}
  async saveRoute(origin,mode,revision){return this.serial(async()=>{const u=endpoint(origin);if(u.origin!==origin||!MODES.includes(mode))fail('INVALID_ROUTES');const routes={...this.value().routes};if(mode==='inherit')delete routes[origin];else routes[origin]=mode;await this.write([{op:'set',path:['routes'],value:routes}],revision);await this.refreshNetwork();return this.state();});}
  /** Opt one configured HTTPS origin into a hostname-verified TLS compatibility handshake. */
  async saveTLSCompatibility(origin,enabled,revision){return this.serial(async()=>{
    const u=endpoint(origin);if(u.origin!==origin||u.protocol!=='https:'||typeof enabled!=='boolean'||!this.routes().some(c=>c.baseURL&&endpoint(c.baseURL).origin===origin))fail('INVALID_TLS_COMPAT');
    const origins=new Set(this.value().tlsCompatOrigins);if(enabled)origins.add(origin);else origins.delete(origin);
    await this.write([{op:'set',path:['tlsCompatOrigins'],value:[...origins]}],revision);await this.refreshNetwork();return this.state();
  });}
  async saveChannel(draft,revision,key){return this.serial(async()=>{
    this.checkRevision(revision);const channels=[...this.value().channels];if(!draft||typeof draft.name!=='string'||!draft.name.trim()||draft.name.length>80||!APIS.includes(draft.api))fail('INVALID_CHANNEL');
    const baseURL=endpoint(draft.baseURL).href.replace(/\/+$/,'');const old=channels.find(c=>c.id===draft.id);if(draft.id&&!old)fail('CHANNEL_NOT_FOUND');
    const id=old?.id||'s'+randomBytes(6).toString('hex');
    if(key!==undefined&&key!==''&&(typeof key!=='string'||key.length>8192||/[\r\n\0]/.test(key)))fail('INVALID_SECRET');
    if(!Array.isArray(draft.models)||draft.models.length>5000)fail('INVALID_MODEL_LIST');
    const models=modelsFrom({data:draft.models});const entry={id,name:draft.name.trim(),baseURL,api:draft.api,models};
    if(old)channels[channels.indexOf(old)]=entry;else channels.push(entry);
    const changes=key?[[credentialRef(id),key.trim()]]:old&&endpoint(old.baseURL).origin!==endpoint(baseURL).origin?[[credentialRef(id),undefined]]:[];
    await this.withCredentials(changes,()=>this.write([{op:'set',path:['channels'],value:channels}],revision));if(!old||old.baseURL!==baseURL||old.api!==entry.api){this.lastResults.delete(providerId(id));this.lastChats?.delete(providerId(id));}try{await this.publish();this.publishError='';}catch(e){this.publishError=errorCode(e);}await this.refreshNetwork();return this.state();
  });}
  async removeChannel(id,revision){return this.serial(async()=>{this.checkRevision(revision);const c=this.value().channels.find(c=>c.id===id);if(!c)fail('CHANNEL_NOT_FOUND');await this.unpublish(c);await this.write([{op:'set',path:['channels'],value:this.value().channels.filter(x=>x.id!==id)}],revision);await this.ctx.credentials.unset(credentialRef(id));await this.refreshNetwork();return this.state();});}
  piNamespace(){
    const counts=new Map();for(const entry of this.ctx.llm.listConfigurableProviders())if(entry.settingsPath?.[0]==='providers')counts.set(entry.settingsNs,(counts.get(entry.settingsNs)||0)+1);
    return [...counts].sort((a,b)=>b[1]-a[1])[0]?.[0];
  }
  async publish(){
    const channels=this.value().channels;if(!channels.length)return;
    const ns=this.piNamespace();if(!ns)fail('PI_AI_SETTINGS_UNAVAILABLE');
    for(let attempt=0;attempt<2;attempt++){
      const section=this.ctx.settings.describe({redactSecrets:false}).find(s=>s.ns===ns);if(!section)fail('PI_AI_SETTINGS_UNAVAILABLE');const providers=section.value?.providers||{};
      const ops=(await Promise.all(channels.map(async c=>{const old=providers[providerId(c.id)]||{};if(!c.models.length){if(!providers[providerId(c.id)])return [];return [{op:'unset',path:['providers',providerId(c.id)]}];}const previous=new Map((old.models||[]).map(m=>[m.id,m]));const value={...old,displayName:c.name,api:c.api,baseURL:c.baseURL,models:c.models.map(m=>({...previous.get(m.id),...m,id:m.id}))};if(await this.configured(credentialRef(c.id)))value.apiKeyEnv=credentialRef(c.id);else delete value.apiKeyEnv;return JSON.stringify(value)===JSON.stringify(old)?[]:[{op:'set',path:['providers',providerId(c.id)],value}];}))).flat();
      if(!ops.length)return;try{await this.ctx.settings.mutate(ns,ops,section.revision);return;}catch(e){if(attempt)throw e;}
    }
  }
  async unpublish(channel){const ns=this.piNamespace();if(!ns)return;const section=this.ctx.settings.describe({redactSecrets:false}).find(s=>s.ns===ns),old=section?.value?.providers?.[providerId(channel.id)];if(!old)return;if(old.baseURL!==channel.baseURL)fail('MANAGED_PROVIDER_CHANGED');await this.ctx.settings.mutate(ns,[{op:'unset',path:['providers',providerId(channel.id)]}],section.revision);}
  route(id){const c=this.routes().find(x=>x.id===id);if(!c||!c.baseURL)fail('ROUTE_NOT_CONFIGURED');return c;}
  async routeHeaders(c){
    const result={accept:'application/json',...(c.managed?{}:c.profile?.headers||{})};
    const ref=c.managed?(await this.configured(credentialRef(c.channelId))?credentialRef(c.channelId):''):c.profile?.apiKeyEnv||c.entry?.apiKeyEnv;const key=ref?await this.secret(ref):'';
    if(ref&&!key)fail('MISSING_CREDENTIAL');if(key){if(c.api==='anthropic-messages'){result['x-api-key']=key;result['anthropic-version']='2023-06-01';}else result.authorization=`Bearer ${key}`;}
    return result;
  }
  async fetchModels(id){return this.serial(async()=>{
    const c=this.route(id);if(!APIS.includes(c.api))fail('DISCOVERY_UNSUPPORTED');const start=Date.now();
    try{const result=await this.network.collect(listingURL(c.baseURL,c.api),{headers:await this.routeHeaders(c)});if(result.status<200||result.status>=300)fail(`HTTP_${result.status}`);let body;try{body=JSON.parse(result.body.toString());}catch{fail('INVALID_MODEL_LIST');}const models=modelsFrom(body);
      if(c.managed&&models.length){const channels=this.value().channels.map(x=>x.id===c.channelId?{...x,models}:x);await this.write([{op:'set',path:['channels'],value:channels}],this.section().revision);await this.publish();}
      this.lastResults.set(id,{ok:true,count:models.length,cached:!models.length,at:Date.now(),elapsedMs:Date.now()-start});
      return {state:await this.state(),result:{models,adopted:c.managed&&models.length>0,emptyRequiresManualEdit:models.length===0}};
    }catch(e){this.lastResults.set(id,{ok:false,code:errorCode(e),cached:true,at:Date.now(),elapsedMs:Date.now()-start});return {state:await this.state(),result:{ok:false,code:errorCode(e),preserved:true}};}
  });}
  async diagnose(id){const c=this.route(id),start=Date.now();try{const result=await this.network.collect(listingURL(c.baseURL,c.api),{headers:await this.routeHeaders(c),limit:1024*1024});return {ok:result.status>=200&&result.status<300,httpStatus:result.status,transportReachable:true,chatVerified:false,elapsedMs:Date.now()-start};}catch(e){return {ok:false,code:errorCode(e),chatVerified:false,elapsedMs:Date.now()-start};}}
  async testChat(id){
    const c=this.route(id);if(this.network.routeStatus(endpoint(c.baseURL)).issue==='PROXY_NOT_CONFIGURED')fail('PROXY_NOT_CONFIGURED');
    const models=c.models.length?c.models:await this.ctx.llm.listModels(c.id);const model=models[0]?.id;if(!model)fail('MODEL_REQUIRED');if(!this.ctx.llm.prepareCall)fail('HOST_CHAT_UNAVAILABLE');
    const call=await this.ctx.llm.prepareCall({provider:c.id,model,maxTokens:24});let finish='',code='';
    for await(const event of call.stream({...call.config,messages:[{role:'user',content:[{type:'text',text:'Reply with OK.'}]}],signal:AbortSignal.timeout(60000)}))if(event.type==='finish'){finish=event.reason?.kind||'';if(event.reason?.failure)code=errorCode(event.reason.failure);}
    const limited=finish==='max-tokens';const result={ok:finish==='stop'||limited,limited,model,finish,code,at:Date.now()};this.lastChats??=new Map();this.lastChats.set(c.id,result);return result;
  }
  ruleHosts(options){return [...new Set([...(options.models?this.routes().filter(c=>c.baseURL&&['smart','proxy'].includes(this.network.policy(endpoint(c.baseURL)))).map(c=>endpoint(c.baseURL).hostname):[]),...(options.github?GITHUB_HOSTS:[]),...(options.npm?['registry.npmjs.org']:[])])].filter(h=>!isLoopback(h));}
  async dispose(){this.closed=true;clearInterval(this.timer);await this.queue.catch(()=>{});await Promise.allSettled([this.gateway.dispose(),this.core.dispose(),this.rules.dispose()]);await this.network.dispose();}
}
