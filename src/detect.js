import net from 'node:net';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { proxyURL } from './config.js';
const run=promisify(execFile);
const normalize=(v)=>{try{return proxyURL(v.includes('://')?v:`http://${v}`);}catch{return '';}};
/** Read the enabled desktop-user proxy; a disabled Windows registry record is not adopted. */
export async function systemProxy(platform=process.platform){
  try{
    if(platform==='win32'){
      const {stdout}=await run('reg',['query','HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'],{timeout:3500,windowsHide:true});
      if(!/ProxyEnable\s+REG_DWORD\s+0x1/i.test(stdout))return {url:'',source:'system',reason:'SYSTEM_PROXY_DISABLED'};
      const server=/ProxyServer\s+REG_SZ\s+([^\r\n]+)/i.exec(stdout)?.[1]?.trim()||'';
      const picked=server.includes('=')?/(?:^|;)https=([^;]+)/i.exec(server)?.[1]||/(?:^|;)http=([^;]+)/i.exec(server)?.[1]||'':server;
      return {url:normalize(picked),source:'system',reason:!picked&&/AutoConfigURL/.test(stdout)?'PAC_REQUIRES_MANUAL':''};
    }
    if(platform==='darwin'){
      const {stdout}=await run('/usr/sbin/scutil',['--proxy'],{timeout:3500});
      for(const type of ['HTTPS','HTTP'])if(new RegExp(`${type}Enable\\s*:\\s*1`).test(stdout)){
        const host=new RegExp(`${type}Proxy\\s*:\\s*(\\S+)`).exec(stdout)?.[1],port=new RegExp(`${type}Port\\s*:\\s*(\\d+)`).exec(stdout)?.[1];
        if(host&&port)return {url:normalize(`${host}:${port}`),source:'system',reason:''};
      }
      return {url:'',source:'system',reason:/ProxyAutoConfigEnable\s*:\s*1/.test(stdout)?'PAC_REQUIRES_MANUAL':'SYSTEM_PROXY_DISABLED'};
    }
    for(const key of ['https_proxy','HTTPS_PROXY','http_proxy','HTTP_PROXY','ALL_PROXY'])if(process.env[key])return {url:normalize(process.env[key]),source:'environment',reason:''};
  }catch{return {url:'',source:'system',reason:'SYSTEM_PROXY_READ_FAILED'};}
  return {url:'',source:'system',reason:'SYSTEM_PROXY_NOT_FOUND'};
}
export function tcpProbe(url,timeout=1000){return new Promise(resolve=>{let s,done=false;const finish=(ok)=>{if(done)return;done=true;s?.destroy();resolve(ok);};try{const u=new URL(url);s=net.connect({host:u.hostname.replace(/^\[|\]$/g,''),port:Number(u.port)|| (u.protocol==='https:'?443:80)});s.setTimeout(timeout,()=>finish(false));s.once('connect',()=>finish(true));s.once('error',()=>finish(false));}catch{finish(false);}});}
/** Listening common ports are suggestions only, never automatically selected as HTTP proxies. */
export async function candidates(){const system=await systemProxy();const ports=await Promise.all([7897,7890,10809,1080,2080].map(async port=>({url:`http://127.0.0.1:${port}`,listening:await tcpProbe(`http://127.0.0.1:${port}`,250)})));return {system,ports:ports.filter(x=>x.listening)};}
