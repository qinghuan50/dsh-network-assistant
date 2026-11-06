import http from 'node:http';
import path from 'node:path';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { context } from 'esbuild';
import { NetworkEngine } from '../src/engine.js';
import { DEFAULTS, NS, errorCode } from '../src/config.js';
import { candidates } from '../src/detect.js';
import { discoverRuleFiles } from '../src/rule-discovery.js';

const dir=path.resolve('.dev-state');await mkdir(dir,{recursive:true,mode:0o700});
const file=path.join(dir,'settings.json'),secretFile=path.join(dir,'credentials.json');
const read=async(p,fallback)=>{try{return JSON.parse(await readFile(p,'utf8'));}catch(e){if(e.code!=='ENOENT')throw e;return fallback;}};
let state=await read(file,{revision:0,value:structuredClone(DEFAULTS),providers:{}}),secrets=await read(secretFile,{});
const credentialWrite=async()=>writeFile(secretFile,JSON.stringify(secrets),{mode:0o600});
const ctx={
  settings:{describe:()=>[{ns:NS,revision:state.revision,value:state.value},{ns:'dev-pi',revision:state.revision,value:{providers:state.providers}}],mutate:async(ns,ops,revision)=>{if(revision!==state.revision)throw new Error('CONFIG_CONFLICT');const value=ns===NS?state.value:{providers:state.providers};for(const op of ops){let target=value;for(const k of op.path.slice(0,-1))target=target[k]??={};if(op.op==='unset')delete target[op.path.at(-1)];else target[op.path.at(-1)]=structuredClone(op.value);}state.revision++;await writeFile(file,JSON.stringify(state),{mode:0o600});}},
  credentials:{resolve:async ref=>secrets[ref]?{value:secrets[ref]}:undefined,describe:async ref=>({configured:!!secrets[ref]}),set:async(ref,value)=>{secrets[ref]=value;await credentialWrite();},unset:async ref=>{delete secrets[ref];await credentialWrite();}},
  llm:{listConfigurableProviders:()=>[{provider:'net-assist-development-directory',settingsNs:'dev-pi',settingsPath:['providers','net-assist-development-directory']},...Object.keys(state.providers).map(provider=>({provider,settingsNs:'dev-pi',settingsPath:['providers',provider]}))],listModels:async provider=>state.providers[provider]?.models||[]},
  logger:{warn:()=>{}},profileContext:{name:'development'},
};
const engine=new NetworkEngine(ctx,{}, {dir:path.join(dir,'runtime')});await engine.initialize();
const build=await context({entryPoints:['dev/client.jsx'],bundle:true,format:'iife',platform:'browser',target:'chrome130',outfile:path.join(dir,'app.js'),loader:{'.css':'text'},define:{'process.env.NODE_ENV':'"development"'}});await build.watch();await build.rebuild();
const token=randomBytes(32).toString('hex'),port=Number(process.env.NA_DEV_PORT||5186),origin=`http://127.0.0.1:${port}`;
const rpc={state:()=>engine.state(),saveConfig:a=>engine.saveConfig(a.draft,a.revision,a.secrets),saveRoute:a=>engine.saveRoute(a.origin,a.mode,a.revision),saveChannel:a=>engine.saveChannel(a.draft,a.revision,a.key),removeChannel:a=>engine.removeChannel(a.id,a.revision),fetchModels:a=>engine.fetchModels(a.id),diagnose:a=>engine.diagnose(a.id),testChat:a=>engine.testChat(a.id),detectProxy:()=>candidates(),refreshProxy:()=>engine.serial(async()=>{await engine.refreshNetwork();return engine.state();}),terminalProbe:a=>engine.gateway.probe(a.workdir),terminalTest:a=>{if(!engine.value().terminalEnabled)throw new Error('TERMINAL_NOT_ENABLED');return engine.gateway.testGit(a.workdir);},terminalScript:a=>{if(!engine.value().terminalEnabled)throw new Error('TERMINAL_NOT_ENABLED');return engine.gateway.script(a.shell);},terminalOpen:a=>{if(!engine.value().terminalEnabled)throw new Error('TERMINAL_NOT_ENABLED');return engine.gateway.open(a.shell);},discoverRules:()=>discoverRuleFiles(),detectRules:()=>engine.rules.detect(),previewRules:a=>engine.serial(()=>engine.rules.preview({hosts:engine.ruleHosts(a.options),group:a.group})),applyRules:a=>engine.serial(()=>engine.rules.apply(a.id)),undoRules:()=>engine.serial(()=>engine.rules.undo()),verifyRules:a=>engine.rules.connections(a.host),startCore:()=>engine.serial(()=>engine.core.start(engine.value().corePath)),stopCore:()=>engine.serial(()=>engine.core.stop()),refreshCore:()=>engine.core.refresh(),selectCore:a=>engine.serial(()=>engine.core.select(a.name))};
const html=`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>DSH 网络助手 · 开发预览</title><style>html,body,#root{margin:0;height:100%;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}.dev-shell{display:grid;grid-template-columns:150px minmax(0,1fr);height:100%;background:light-dark(#fff,#171a20)}.dev-shell>aside{background:light-dark(#f4f5f7,#1d2026);color:light-dark(#75808e,#a2abba);padding:24px 12px;display:flex;flex-direction:column;gap:12px;font-size:13px;border-right:1px solid light-dark(#e9ecf1,#333944)}.dev-shell aside>div:not(.dev-brand){padding:7px 10px}.dev-brand{display:flex;gap:9px;padding:0 8px 25px;color:light-dark(#202632,#e5e9f0);font-size:14px}.dev-brand>svg{color:light-dark(#3666d8,#87abff)}.dev-brand small{font-size:12px;color:light-dark(#75808e,#a2abba)}.dev-shell aside>p{margin:10px;font-size:11px}.dev-selected{display:flex;align-items:center;gap:8px;background:light-dark(#fff,#171a20);border-radius:7px;color:light-dark(#3666d8,#87abff)}.dev-selected svg{width:16px;height:16px}.dev-foot{margin-top:auto;padding:15px 7px;font-size:11px}@media(max-width:620px){.dev-shell{grid-template-columns:1fr}.dev-shell>aside{display:none}}</style></head><body><div id="root"></div><script src="/app.js"></script></body></html>`;
const server=http.createServer(async(req,res)=>{
  res.setHeader('cache-control','no-store');res.setHeader('x-content-type-options','nosniff');
  if(req.headers.host!==`127.0.0.1:${port}`){res.writeHead(403);res.end();return;}
  if(req.method==='GET'&&req.url==='/'){res.setHeader('set-cookie',`na_session=${token}; HttpOnly; SameSite=Strict; Path=/`);res.setHeader('content-type','text/html; charset=utf-8');res.end(html);return;}
  if(req.method==='GET'&&req.url==='/app.js'){res.setHeader('content-type','text/javascript; charset=utf-8');res.end(await readFile(path.join(dir,'app.js')));return;}
  if(req.url!=='/api'||req.method!=='POST'){res.writeHead(404);res.end();return;}
  const provided=/na_session=([a-f0-9]+)/.exec(req.headers.cookie||'')?.[1]||'';
  if(req.headers.origin!==origin||provided.length!==token.length||!timingSafeEqual(Buffer.from(provided),Buffer.from(token))){res.writeHead(403,{'content-type':'application/json'});res.end('{"code":"OWNER_ONLY"}');return;}
  try{let data='',size=0;for await(const chunk of req){size+=chunk.length;if(size>2*1024*1024)throw new Error('REQUEST_TOO_LARGE');data+=chunk;}const body=JSON.parse(data);if(!Object.hasOwn(rpc,body.method))throw new Error('UNKNOWN_METHOD');const value=await rpc[body.method](body.args||{});res.setHeader('content-type','application/json');res.end(JSON.stringify({value}));}
  catch(e){res.writeHead(400,{'content-type':'application/json'});res.end(JSON.stringify({code:errorCode(e)}));}
});
await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',resolve);});
console.log(`Network Assistant development UI: ${origin}`);
let stopping=false;async function stop(){if(stopping)return;stopping=true;server.closeAllConnections();server.close();await engine.dispose();await build.dispose();process.exit(0);}process.once('SIGINT',stop);process.once('SIGTERM',stop);
