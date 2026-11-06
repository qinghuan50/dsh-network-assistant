import { isIP } from 'node:net';

export const NS='local-network-assistant';
export const MODES=['inherit','direct','smart','proxy'];
export const APIS=['openai-completions','openai-responses','anthropic-messages'];
export const DEFAULTS={mode:'inherit',paused:false,showSidebar:true,source:'system',proxyUrl:'',bypass:'',terminalEnabled:false,controllerURL:'http://127.0.0.1:9090',effectivePath:'',scriptPath:'',ruleClient:'verge',corePath:'',channels:[],routes:{},tlsCompatOrigins:[]};
export const fail=(code)=>{throw new Error(code);};
export const credentialRef=(id)=>`NA_MODEL_${String(id).replace(/[^a-z0-9]/gi,'').toUpperCase()}`;
export const providerId=(id)=>`net-assist-${id}`;
export function errorCode(error){let e=error;for(let depth=0;e&&depth<6;depth++,e=e.cause||e.errors?.[0]){if(/^[A-Z][A-Z_0-9]{1,70}$/.test(e.code||''))return e.code;if(/^[A-Z][A-Z_0-9]{1,70}$/.test(e.message||''))return e.message;}return 'OPERATION_FAILED';}
export function endpoint(raw){
  let u;try{u=new URL(String(raw).trim());}catch{fail('INVALID_ENDPOINT');}
  if(!['http:','https:'].includes(u.protocol)||u.username||u.password||u.search||u.hash)fail('INVALID_ENDPOINT');
  return u;
}
export function proxyURL(raw){const u=endpoint(raw);if(u.pathname!=='/')fail('INVALID_PROXY');return u.href.replace(/\/$/,'');}
/** Loopback never enters the external proxy, including IPv4-mapped IPv6 forms. */
export function isLoopback(raw){
  const h=String(raw).replace(/^\[|\]$/g,'').replace(/\.$/,'').toLowerCase();
  if(h==='localhost'||h.endsWith('.localhost')||['::1','::','0.0.0.0'].includes(h))return true;
  if(isIP(h)===4)return h.split('.')[0]==='127';
  if(h.startsWith('::ffff:')){const tail=h.slice(7);if(isIP(tail)===4)return tail.startsWith('127.');const first=tail.split(':')[0];return /^[0-9a-f]{1,4}$/i.test(first)&&(parseInt(first,16)>>>8)===127;}
  return false;
}
export function bypasses(host,list){const h=host.replace(/^\[|\]$/g,'').replace(/\.$/,'').toLowerCase();return String(list||'').split(/[,\s]+/).filter(Boolean).some(x=>{const p=x.toLowerCase().replace(/^\*?\./,'').replace(/\.$/,'');return p==='*'||h===p||h.endsWith(`.${p}`);});}
export function normalize(raw={}){
  const v={...DEFAULTS,...raw};
  if(!MODES.includes(v.mode)||!['system','manual','core'].includes(v.source)||!['verge','mihomo','other'].includes(v.ruleClient))fail('INVALID_CONFIG');
  for(const k of ['paused','showSidebar','terminalEnabled'])if(typeof v[k]!=='boolean')fail('INVALID_CONFIG');
  for(const k of ['proxyUrl','bypass','controllerURL','effectivePath','scriptPath','corePath'])if(typeof v[k]!=='string'||v[k].length>8192||v[k].includes('\0'))fail('INVALID_CONFIG');
  if(v.proxyUrl)v.proxyUrl=proxyURL(v.proxyUrl);
  const control=endpoint(v.controllerURL);if(!isLoopback(control.hostname)||control.pathname!=='/')fail('CONTROLLER_MUST_BE_LOOPBACK');
  if(!Array.isArray(v.channels)||v.channels.length>300)fail('INVALID_CHANNELS');
  if(!v.routes||typeof v.routes!=='object'||Array.isArray(v.routes)||Object.keys(v.routes).length>500)fail('INVALID_ROUTES');
  for(const [origin,mode]of Object.entries(v.routes)){if(endpoint(origin).origin!==origin||!MODES.includes(mode))fail('INVALID_ROUTES');}
  if(!Array.isArray(v.tlsCompatOrigins)||v.tlsCompatOrigins.length>500)fail('INVALID_TLS_COMPAT');
  for(const origin of v.tlsCompatOrigins){const u=endpoint(origin);if(u.origin!==origin||u.protocol!=='https:')fail('INVALID_TLS_COMPAT');}
  v.tlsCompatOrigins=[...new Set(v.tlsCompatOrigins)];
  return v;
}
/** Normalize only host-owned model fields; a directory failure never replaces this array. */
export function modelsFrom(payload){
  const rows=Array.isArray(payload?.data)?payload.data:Array.isArray(payload?.models)?payload.models:payload?.models&&typeof payload.models==='object'?Object.entries(payload.models).map(([id,x])=>({...x,id})):null;
  if(!rows||rows.length>5000)fail('INVALID_MODEL_LIST');
  const seen=new Set();return rows.flatMap(x=>{
    if(!x||typeof x!=='object')return [];
    const id=String(x.id||x.model||'').trim();if(!id||id.length>512||seen.has(id))return [];seen.add(id);
    const positive=(...a)=>a.find(n=>Number.isSafeInteger(n)&&n>0);
    const contextWindow=positive(x.contextWindow,x.context_window,x.context_length,x.limit?.context);
    const maxTokens=positive(x.maxTokens,x.max_tokens,x.max_completion_tokens,x.limit?.output);
    return [{id,name:String(x.name||x.display_name||id).slice(0,160),...(contextWindow?{contextWindow}:{}),...(maxTokens?{maxTokens}:{})}];
  });
}
export function listingURL(base,api){const u=endpoint(base);let p=u.pathname.replace(/\/+$/,'');if(api==='anthropic-messages')p=p.replace(/\/v1$/,'')+'/v1';u.pathname=p+'/models';return u.href;}
export const safeHeaders=(headers)=>Object.fromEntries(Object.entries(headers||{}).filter(([k])=>!['proxy-authorization','connection','host','transfer-encoding','upgrade','keep-alive','content-length','te','trailer'].includes(k.toLowerCase())));
