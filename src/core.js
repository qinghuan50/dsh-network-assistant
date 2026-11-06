import { mkdir, writeFile, chmod, rm, access } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import net from 'node:net';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { Agent, request } from 'undici';
import { fail } from './config.js';
const freePort=()=>new Promise((resolve,reject)=>{const s=net.createServer();s.once('error',reject);s.listen(0,'127.0.0.1',()=>{const port=s.address().port;s.close(()=>resolve(port));});});

/** Optional user-supplied mihomo binary. All listeners are loopback; no TUN or system proxy changes. */
export class CoreManager {
  constructor({dir,secret,onChange=()=>{}}){this.dir=dir;this.secret=secret;this.onChange=onChange;this.child=null;this.agent=new Agent();this.controllerSecret=randomBytes(24).toString('hex');this.lastError='';this.nodes=[];}
  get running(){return !!this.child&&this.child.exitCode===null&&!this.child.killed;}
  get proxyURL(){return this.running?`http://127.0.0.1:${this.port}`:'';}
  status(){return {running:this.running,proxyURL:this.proxyURL,nodes:this.nodes,lastError:this.lastError};}
  async api(route,{method='GET',body}={}){
    if(!this.running)fail('CORE_NOT_RUNNING');const res=await request(`http://127.0.0.1:${this.controlPort}${route}`,{method,dispatcher:this.agent,headers:{authorization:`Bearer ${this.controllerSecret}`,...(body?{'content-type':'application/json'}:{})},body:body?JSON.stringify(body):undefined,signal:AbortSignal.timeout(3000),maxRedirections:0});
    const chunks=[];let size=0;try{for await(const b of res.body){size+=b.length;if(size>2*1024*1024)fail('CORE_REPLY_TOO_LARGE');chunks.push(b);}}finally{res.body.destroy();}if(res.statusCode<200||res.statusCode>=300)fail(`CORE_HTTP_${res.statusCode}`);const text=Buffer.concat(chunks).toString();return text?JSON.parse(text):{};
  }
  async start(binary){
    if(this.running)return this.status();if(!path.isAbsolute(binary))fail('CORE_PATH_REQUIRED');await access(binary);
    const subscription=await this.secret();if(!subscription)fail('CORE_SUBSCRIPTION_REQUIRED');let u;try{u=new URL(subscription);}catch{fail('INVALID_SUBSCRIPTION');}if(u.username||u.password||u.hash)fail('INVALID_SUBSCRIPTION');
    // Subscription query strings are meaningful credentials and are handled separately from API endpoints.
    if(u.protocol!=='https:'&&!(u.protocol==='http:'&&['localhost','127.0.0.1'].includes(u.hostname)))fail('HTTPS_SUBSCRIPTION_REQUIRED');
    await mkdir(this.dir,{recursive:true,mode:0o700});this.port=await freePort();this.controlPort=await freePort();
    const config={ 'mixed-port':this.port,'bind-address':'127.0.0.1','allow-lan':false,'external-controller':`127.0.0.1:${this.controlPort}`,secret:this.controllerSecret,mode:'rule','log-level':'silent','proxy-providers':{subscription:{type:'http',url:subscription,path:'./subscription.yaml',interval:3600}},'proxy-groups':[{name:'NA_PROXY',type:'select',use:['subscription']}],rules:['MATCH,NA_PROXY']};
    this.configFile=path.join(this.dir,'config.json');await writeFile(this.configFile,JSON.stringify(config),{mode:0o600});await chmod(this.configFile,0o600);
    const child=spawn(binary,['-d',this.dir,'-f',this.configFile],{windowsHide:true,stdio:'ignore'});this.child=child;this.lastError='';
    child.on('error',()=>{this.lastError='CORE_START_FAILED';if(this.child===child)this.child=null;this.onChange();});
    child.on('exit',code=>{if(this.child===child){this.child=null;this.nodes=[];if(code)this.lastError='CORE_EXITED';void rm(this.configFile,{force:true});void this.onChange();}});
    for(let n=0;n<35;n++){
      if(!this.running)break;
      try{const data=await this.api('/proxies/NA_PROXY');this.nodes=Array.isArray(data.all)?data.all:[];await this.onChange();return this.status();}catch{}
      await new Promise(r=>setTimeout(r,200));
    }
    await this.stop();fail('CORE_START_TIMEOUT');
  }
  async refresh(){const data=await this.api('/proxies/NA_PROXY');this.nodes=Array.isArray(data.all)?data.all:[];return this.status();}
  async select(name){if(typeof name!=='string'||!this.nodes.includes(name))fail('INVALID_CORE_NODE');await this.api('/proxies/NA_PROXY',{method:'PUT',body:{name}});return this.refresh();}
  async stop(){const child=this.child;this.child=null;this.nodes=[];if(child&&child.exitCode===null){const exit=new Promise(r=>child.once('exit',r));child.kill();await Promise.race([exit,new Promise(r=>setTimeout(r,1500))]);if(child.exitCode===null){child.kill('SIGKILL');await Promise.race([exit,new Promise(r=>setTimeout(r,1500))]);}}await Promise.all([this.configFile?rm(this.configFile,{force:true}):undefined,rm(path.join(this.dir,'subscription.yaml'),{force:true})]);await this.onChange();return this.status();}
  async dispose(){await this.stop();await this.agent.destroy();}
}
