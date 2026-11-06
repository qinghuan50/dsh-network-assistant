import { readFile, realpath, stat, mkdir, writeFile, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { Agent, request } from 'undici';
import yaml from 'js-yaml';
import { endpoint, fail, isLoopback } from './config.js';

const hash=(s)=>createHash('sha256').update(s).digest('hex');
export const GITHUB_HOSTS=['github.com','api.github.com','codeload.github.com','raw.githubusercontent.com','objects.githubusercontent.com','release-assets.githubusercontent.com'];
async function atomic(file,text,mode=0o600){const temp=file+'.na-'+randomBytes(5).toString('hex');try{await writeFile(temp,text,{mode});await rename(temp,file);}finally{await rm(temp,{force:true});}}
async function inputFile(raw,extension){if(!path.isAbsolute(raw)||!extension.test(raw))fail('INVALID_CONFIG_PATH');const filename=await realpath(raw),info=await stat(filename);if(!info.isFile()||info.size>8*1024*1024)fail('CONFIG_FILE_TOO_LARGE');return {path:filename,text:await readFile(filename,'utf8'),mode:info.mode&0o777};}
export function activeLeaf(proxies,name,seen=new Set()){
  if(seen.has(name))return null;seen.add(name);const p=proxies[name];if(!p||/^(DIRECT|REJECT|REJECT-DROP|PASS|DNS)$/i.test(name)||/^(Direct|Reject|RejectDrop|Pass|Dns)$/i.test(p.type))return null;
  if(p.now)return activeLeaf(proxies,p.now,seen);
  if(Array.isArray(p.all))return null;
  return {name,type:p.type};
}
/** Wrap the original synchronous Verge main without executing user script inside the Host. */
export function vergeScript(original,rules){
  return `// Managed by DSH Network Assistant. Restore through the plugin before manual editing.\nconst __dshOriginalMain = (function () {\n${original}\n;return typeof main === 'function' ? main : null;\n})();\nfunction main(config, profileName) {\n const next = __dshOriginalMain ? __dshOriginalMain(config, profileName) : config;\n if (!next || !Array.isArray(next.rules)) throw new Error('Network Assistant: invalid rules');\n const managed = ${JSON.stringify(rules)};\n next.rules = managed.concat(next.rules.filter(rule => managed.indexOf(rule) < 0));\n return next;\n}\n`;
}
/** Owner-triggered file/config operations use expiring previews, content hashes and recoverable snapshots. */
export class RuleManager {
  constructor({dir,config,secret}){this.dir=dir;this.config=config;this.secret=secret;this.agent=new Agent();this.plans=new Map();this.snapshotPath=path.join(dir,'rules-snapshot.json');}
  async api(route,{method='GET',body,config=this.config()}={}){
    const base=endpoint(config.controllerURL);if(!isLoopback(base.hostname))fail('CONTROLLER_MUST_BE_LOOPBACK');
    const token=await this.secret();const res=await request(new URL(route,base),{method,dispatcher:this.agent,headers:{accept:'application/json',...(token?{authorization:`Bearer ${token}`}:{}) ,...(body?{'content-type':'application/json'}:{})},body:body?JSON.stringify(body):undefined,signal:AbortSignal.timeout(7000),headersTimeout:7000,bodyTimeout:7000,maxRedirections:0});
    const chunks=[];let size=0;try{for await(const chunk of res.body){size+=chunk.length;if(size>8*1024*1024)fail('CONTROLLER_REPLY_TOO_LARGE');chunks.push(chunk);}}finally{res.body.destroy();}
    if(res.statusCode<200||res.statusCode>=300)fail(`CONTROLLER_HTTP_${res.statusCode}`);const text=Buffer.concat(chunks).toString('utf8');if(!text)return {};try{return JSON.parse(text);}catch{fail('INVALID_CONTROLLER_REPLY');}
  }
  async detect(){
    const [version,result]=await Promise.all([this.api('/version'),this.api('/proxies')]);
    const proxies=result.proxies||{};return {connected:true,version:String(version.version||''),groups:Object.entries(proxies).filter(([,p])=>Array.isArray(p.all)).map(([name,p])=>({name,type:p.type,now:p.now||'',leaf:activeLeaf(proxies,name)?.name||'',usable:!!activeLeaf(proxies,name)}))};
  }
  async snapshot(){try{return JSON.parse(await readFile(this.snapshotPath,'utf8'));}catch(e){if(e.code==='ENOENT')return null;fail('SNAPSHOT_UNREADABLE');}}
  async status(){const s=await this.snapshot();return s?{managed:true,stage:s.stage,group:s.group,hosts:s.hosts,appliedAt:s.appliedAt}: {managed:false};}
  async preview({hosts,group}){
    if(!Array.isArray(hosts)||!hosts.length||hosts.length>200||typeof group!=='string'||!group||/[\r\n,]/.test(group))fail('INVALID_RULE_PLAN');
    const targets=[...new Set(hosts.map(raw=>{const u=endpoint(`https://${raw}`);if(u.hostname!==raw||isLoopback(raw)||!/[a-z]/i.test(raw))fail('INVALID_RULE_HOST');return raw;}))];
    const config=this.config(),rules=targets.map(host=>`DOMAIN,${host},${group}`);
    if(config.ruleClient==='other')return {supported:false,rules,hosts:targets,group,reason:'CLIENT_ADAPTER_REQUIRED'};
    const proxies=(await this.api('/proxies')).proxies||{};if(!activeLeaf(proxies,group))fail('GROUP_DOES_NOT_PROXY');
    const previous=await this.snapshot();if(previous&&previous.stage!=='applied')fail('RECOVERY_REQUIRED');
    const effective=await inputFile(config.effectivePath,/\.ya?ml$/i);
    if(previous&&(previous.client!==config.ruleClient||previous.files[0].path!==effective.path))fail('UNDO_RULES_BEFORE_CONFIG_CHANGE');
    if(previous&&previous.files.some(f=>f.path===effective.path&&f.afterHash!==hash(effective.text)))fail('MANAGED_FILE_CHANGED');
    let data;try{data=yaml.load(effective.text);}catch{fail('INVALID_YAML');}if(!data||!Array.isArray(data.rules))fail('INVALID_RULES_CONFIG');
    const oldOwned=new Set(previous?.rules||[]),rest=data.rules.filter(r=>!oldOwned.has(r));
    const conflicts=rest.filter(r=>typeof r==='string'&&targets.some(host=>r.startsWith(`DOMAIN,${host},`)||r.startsWith(`DOMAIN-SUFFIX,${host},`))&&!rules.includes(r));
    data.rules=[...rules,...rest.filter(r=>!rules.includes(r))];
    const files=[{...effective,after:yaml.dump(data,{lineWidth:-1,noRefs:true})}];
    if(config.ruleClient==='verge'){
      const script=await inputFile(config.scriptPath,/\.js$/i);if(script.path===effective.path)fail('INVALID_CONFIG_PATH');
      if(previous&&!previous.files.some(f=>f.path===script.path))fail('UNDO_RULES_BEFORE_CONFIG_CHANGE');
      const old=previous?.files.find(f=>f.path===script.path);
      if(old&&old.afterHash!==hash(script.text))fail('MANAGED_FILE_CHANGED');
      const original=old?.original??script.text;files.push({...script,after:vergeScript(original,rules),original});
    }
    for(const file of files){file.beforeHash=hash(file.text);file.afterHash=hash(file.after);file.original??=previous?.files.find(f=>f.path===file.path)?.original??file.text;}
    const id=randomBytes(18).toString('hex');this.plans.clear();this.plans.set(id,{id,expires:Date.now()+5*60000,config:JSON.stringify(config),files,rules,hosts:targets,group,previous});
    return {id,supported:true,rules,conflicts,hosts:targets,group,files:files.map(f=>f.path),persistent:true,affectsOtherApplications:true,expiresAt:Date.now()+5*60000};
  }
  async verifyRules(plan){const res=await this.api('/rules');return plan.hosts.every(h=>(res.rules||[]).some(r=>r.type==='Domain'&&r.payload===h&&r.proxy===plan.group||r.type==='DOMAIN'&&r.payload===h&&r.proxy===plan.group));}
  async reload(filename){await this.api('/configs?force=true',{method:'PUT',body:{path:filename}});}
  async saveSnapshot(snapshot){await mkdir(this.dir,{recursive:true,mode:0o700});await atomic(this.snapshotPath,JSON.stringify(snapshot));}
  async apply(id){
    const p=this.plans.get(id);if(!p||p.expires<Date.now())fail('PREVIEW_EXPIRED');if(p.config!==JSON.stringify(this.config()))fail('CONFIG_CONFLICT');
    for(const f of p.files)if(hash(await readFile(f.path,'utf8'))!==f.beforeHash)fail('CONFIG_FILE_CHANGED');
    if(!activeLeaf((await this.api('/proxies')).proxies||{},p.group))fail('GROUP_DOES_NOT_PROXY');
    const snapshot={stage:'pending',client:this.config().ruleClient,group:p.group,hosts:p.hosts,rules:p.rules,appliedAt:Date.now(),files:p.files.map(f=>({path:f.path,original:f.original,after:f.after,afterHash:f.afterHash,mode:f.mode})),rollback:p.files.map(f=>({path:f.path,text:f.text,mode:f.mode})),previous:p.previous};
    await this.saveSnapshot(snapshot);
    try{
      for(const f of p.files)await atomic(f.path,f.after,f.mode);
      await this.reload(p.files[0].path);if(!await this.verifyRules(p))fail('RULES_NOT_ACTIVE');if(!activeLeaf((await this.api('/proxies')).proxies||{},p.group))fail('GROUP_DOES_NOT_PROXY');
      snapshot.stage='applied';delete snapshot.rollback;delete snapshot.previous;await this.saveSnapshot(snapshot);this.plans.clear();
      return {configured:true,reloaded:true,rulesVerified:true,trafficVerified:false,...await this.status()};
    }catch(e){
      try{for(const f of snapshot.rollback)await atomic(f.path,f.text,f.mode);await this.reload(p.files[0].path);if(p.previous)await this.saveSnapshot(p.previous);else await rm(this.snapshotPath,{force:true});}
      catch{snapshot.stage='recovery-required';await this.saveSnapshot(snapshot);fail('RECOVERY_REQUIRED');}
      throw e;
    }
  }
  /** Undo restores only files whose current hash still matches this manager's last write. */
  async undo(){
    const s=await this.snapshot();if(!s)return {managed:false};if(s.stage!=='applied')return this.recover();
    for(const f of s.files)if(hash(await readFile(f.path,'utf8'))!==f.afterHash)fail('MANAGED_FILE_CHANGED');
    await this.saveSnapshot({...s,stage:'undo-pending'});
    try{for(const f of s.files)await atomic(f.path,f.original,f.mode);await this.reload(s.files[0].path);await rm(this.snapshotPath,{force:true});return {managed:false,reloaded:true};}
    catch(e){try{for(const f of s.files)await atomic(f.path,f.after,f.mode);await this.reload(s.files[0].path);await this.saveSnapshot(s);}catch{fail('RECOVERY_REQUIRED');}throw e;}
  }
  async recover(){const s=await this.snapshot();if(s?.stage==='undo-pending'){for(const f of s.files){const current=hash(await readFile(f.path,'utf8'));if(current!==f.afterHash&&current!==hash(f.original))fail('MANAGED_FILE_CHANGED');}for(const f of s.files)await atomic(f.path,f.original,f.mode);await this.reload(s.files[0].path);await rm(this.snapshotPath,{force:true});return {managed:false,reloaded:true};}if(!s||!s.rollback)fail('RECOVERY_REQUIRED');for(const f of s.files){const current=hash(await readFile(f.path,'utf8')),before=s.rollback.find(r=>r.path===f.path);if(current!==f.afterHash&&current!==hash(before.text))fail('MANAGED_FILE_CHANGED');}for(const f of s.rollback)await atomic(f.path,f.text,f.mode);await this.reload(s.files[0].path);if(s.previous)await this.saveSnapshot(s.previous);else await rm(this.snapshotPath,{force:true});return this.status();}
  async connections(host){const data=await this.api('/connections');return (data.connections||[]).filter(c=>c.metadata?.host===host).slice(0,10).map(c=>({host,rule:c.rule,rulePayload:c.rulePayload,chains:c.chains||[],startedAt:c.start}));}
  async dispose(){await this.agent.destroy();this.plans.clear();}
}
