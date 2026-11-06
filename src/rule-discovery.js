import path from 'node:path';
import os from 'node:os';
import { readFile, stat } from 'node:fs/promises';
import yaml from 'js-yaml';
import { isLoopback } from './config.js';

/** Inspect only known client configuration filenames, not the home directory recursively. */
export async function discoverRuleFiles(){
  const home=os.homedir();const bases=process.platform==='win32'?[process.env.APPDATA,process.env.LOCALAPPDATA].filter(Boolean):process.platform==='darwin'?[path.join(home,'Library','Application Support'),path.join(home,'.config')]:[process.env.XDG_CONFIG_HOME||path.join(home,'.config')];
  const roots=bases.flatMap(base=>['io.github.clash-verge-rev.clash-verge-rev','clash-verge','clash-verge-rev','mihomo'].map(name=>path.join(base,name)));
  const found=[];
  for(const root of roots)for(const name of ['clash-verge.yaml','clash-verge.yml','config.yaml']){
    const effectivePath=path.join(root,name);try{
      const info=await stat(effectivePath);if(!info.isFile()||info.size>8*1024*1024)continue;
      const config=yaml.load(await readFile(effectivePath,'utf8'));if(!Array.isArray(config?.rules))continue;
      let controllerURL='';const raw=config['external-controller'];if(typeof raw==='string'&&raw&&!raw.startsWith('/')){const u=new URL(raw.includes('://')?raw:`http://${raw}`);if(u.hostname==='0.0.0.0'||u.hostname==='[::]')u.hostname='127.0.0.1';if(isLoopback(u.hostname))controllerURL=u.origin;}
      let scriptPath='';const script=path.join(root,'profiles','Script.js');try{if((await stat(script)).isFile())scriptPath=script;}catch{}
      found.push({ruleClient:name.startsWith('clash-verge')?'verge':'mihomo',effectivePath,scriptPath,controllerURL,controllerSecretPresent:typeof config.secret==='string'&&!!config.secret});
    }catch{}
  }
  return {candidates:found};
}

/** Secret fallback is read only from the exact file the owner selected, and stays in the Host. */
export async function controllerSecretFromFile(filename){
  if(!filename||!path.isAbsolute(filename))return '';
  try{const info=await stat(filename);if(!info.isFile()||info.size>8*1024*1024)return '';const data=yaml.load(await readFile(filename,'utf8'));return typeof data?.secret==='string'?data.secret:'';}catch{return '';}
}
