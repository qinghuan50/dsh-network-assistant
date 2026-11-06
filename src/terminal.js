import http from 'node:http';
import net from 'node:net';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, writeFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { request } from 'undici';
import { safeHeaders, fail, isLoopback, errorCode } from './config.js';
const run=promisify(execFile);
const parentEnv=()=>Object.fromEntries(Object.entries(process.env).filter(([k])=>!/(?:KEY|PASSWORD|SECRET|TOKEN)/i.test(k)&&!k.toUpperCase().startsWith('DSH_')));
const HOP=new Set(['connection','proxy-connection','proxy-authorization','proxy-authenticate','upgrade','keep-alive','transfer-encoding','te','trailer']);
function headers(input){const extra=String(input.connection||'').toLowerCase().split(',').map(x=>x.trim());return Object.fromEntries(Object.entries(input).filter(([k])=>!HOP.has(k.toLowerCase())&&!extra.includes(k.toLowerCase())));}

/** Explicit authenticated HTTP/CONNECT gateway for local tools; never decrypts TLS or replays requests. */
export class TerminalGateway {
  constructor(network,{dir,record=()=>{}}){this.network=network;this.dir=dir;this.record=record;this.server=null;this.sockets=new Set();this.sessions=[];this.user='dsh';this.password=randomBytes(24).toString('hex');this.authorization=`Basic ${Buffer.from(`${this.user}:${this.password}`).toString('base64')}`;}
  authorized(req){const actual=Buffer.from(req.headers['proxy-authorization']||''),expected=Buffer.from(this.authorization);return actual.length===expected.length&&timingSafeEqual(actual,expected);}
  async start(){
    if(this.server)return;
    const server=http.createServer((req,res)=>{this.forward(req,res).catch(e=>{if(!res.headersSent)res.writeHead(502,{'content-type':'text/plain'});res.end(errorCode(e));});});
    server.on('connect',(req,client,head)=>{this.connect(req,client,head).catch(e=>{if(!client.destroyed)client.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n');});});
    server.on('connection',s=>{if(this.sockets.size>=128){s.destroy();return;}this.sockets.add(s);s.once('close',()=>this.sockets.delete(s));});
    server.headersTimeout=15000;server.requestTimeout=0;server.maxHeadersCount=100;
    server.on('clientError',(_,s)=>s.destroy());
    await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',()=>{server.off('error',reject);resolve();});});
    this.server=server;this.port=server.address().port;
  }
  get url(){return this.server?`http://${this.user}:${this.password}@127.0.0.1:${this.port}`:'';}
  async forward(req,res){
    if(!this.authorized(req)){res.writeHead(407,{'proxy-authenticate':'Basic realm="DSH Network Assistant"'});res.end();return;}
    let target;try{target=new URL(req.url);}catch{fail('INVALID_ENDPOINT');}
    if(!['http:','https:'].includes(target.protocol)||target.username||target.password)fail('INVALID_ENDPOINT');
    if(isLoopback(target.hostname)&&Number(target.port)===this.port)fail('PROXY_LOOP');
    const abort=new AbortController();req.once('aborted',()=>abort.abort());res.once('close',()=>abort.abort());
    const upstream=await request(target,{method:req.method,headers:safeHeaders(headers(req.headers)),body:['GET','HEAD'].includes(req.method)?undefined:req,dispatcher:this.network.toolDispatcher(),signal:abort.signal,headersTimeout:30000,bodyTimeout:0,maxRedirections:0});
    res.writeHead(upstream.statusCode,headers(upstream.headers));upstream.body.once('error',()=>res.destroy());upstream.body.pipe(res);
  }
  async connect(req,client,head){
    client.on('error',()=>{});
    if(!this.authorized(req)){client.end('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="DSH Network Assistant"\r\n\r\n');return;}
    if(!/^(?:\[[0-9a-f:]+\]|[a-z0-9._-]+):[0-9]+$/i.test(req.url))fail('INVALID_ENDPOINT');
    const target=new URL(`https://${req.url}`),port=Number(target.port)||443;if(port<1||port>65535)fail('INVALID_ENDPOINT');
    if(isLoopback(target.hostname)&&port===this.port)fail('PROXY_LOOP');
    const start=Date.now();let upstream;
    try{
      const result=await this.network.socket(target,{raw:true,tool:true});upstream=result.socket;
      if(client.destroyed){upstream.destroy();return;}
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');if(head.length)upstream.write(head);
      upstream.on('error',()=>client.destroy());client.on('error',()=>upstream.destroy());client.on('close',()=>upstream.destroy());upstream.on('close',()=>client.destroy());
      client.pipe(upstream);upstream.pipe(client);
      this.record({at:Date.now(),origin:target.origin,method:'CONNECT',kind:'tunnel',mode:this.network.policy(target,true),via:result.via,status:200,code:'',elapsedMs:Date.now()-start});
    }catch(e){upstream?.destroy();this.record({at:Date.now(),origin:target.origin,method:'CONNECT',kind:'tunnel',via:'',status:0,code:errorCode(e),elapsedMs:Date.now()-start});throw e;}
  }
  /** Only new local windows inherit these values. Existing process environments are untouched. */
  environment(){
    if(!this.server)fail('TERMINAL_NOT_ENABLED');
    // Git's http.proxy config can override environment proxies. The session-only config
    // makes new windows deterministic without changing repository or global Git files.
    return {HTTP_PROXY:this.url,HTTPS_PROXY:this.url,ALL_PROXY:this.url,http_proxy:this.url,https_proxy:this.url,all_proxy:this.url,NO_PROXY:'localhost,127.0.0.1,::1',no_proxy:'localhost,127.0.0.1,::1',GIT_CONFIG_COUNT:'1',GIT_CONFIG_KEY_0:'http.proxy',GIT_CONFIG_VALUE_0:this.url,GIT_CONFIG_PARAMETERS:''};
  }
  async script(shell){
    if(!['cmd','pwsh','system'].includes(shell))fail('INVALID_SHELL');
    const env=this.environment();await mkdir(this.dir,{recursive:true,mode:0o700});
    const file=path.join(this.dir,`session-${randomBytes(6).toString('hex')}.${shell==='cmd'?'cmd':shell==='pwsh'?'ps1':'command'}`);
    // Gateway URL uses generated ASCII credentials, so it cannot inject shell syntax.
    const text=shell==='cmd'?`@echo off\r\n${Object.entries(env).filter(([k])=>k===k.toUpperCase()).map(([k,v])=>`set "${k}=${v}"`).join('\r\n')}\r\necho [DSH] Session proxy active. Close this window before unloading Network Assistant.\r\n`:shell==='pwsh'?`${Object.entries(env).filter(([k])=>k===k.toUpperCase()).map(([k,v])=>`$env:${k} = '${v}'`).join('\n')}\nWrite-Host '[DSH] Session proxy active. Close this window before unloading Network Assistant.'\n`:`#!/bin/sh\n${Object.entries(env).map(([k,v])=>`export ${k}='${v}'`).join('\n')}\nprintf '%s\\n' '[DSH] Session proxy active. Close before unloading Network Assistant.'\nexec /bin/zsh -i\n`;
    await writeFile(file,text,{mode:0o700});this.sessions.push(file);return {path:file,shell};
  }
  async open(shell){
    if(!['cmd','pwsh','system'].includes(shell))fail('INVALID_SHELL');
    if(process.platform!=='win32'&&shell!=='system')fail('SHELL_NOT_AVAILABLE');
    if(process.platform==='win32'&&shell==='system')shell='pwsh';
    if(process.platform!=='win32'&&process.platform!=='darwin')fail('USE_SESSION_SCRIPT');
    const file=await this.script(shell);let child;
    if(process.platform==='win32')child=spawn(shell==='cmd'?'cmd.exe':'powershell.exe',shell==='cmd'?['/D','/K',file.path]:['-NoProfile','-NoExit','-File',file.path],{detached:true,stdio:'ignore',windowsHide:false,env:parentEnv()});
    else child=spawn('/usr/bin/open',['-a','Terminal',file.path],{stdio:'ignore',env:parentEnv()});
    await new Promise((resolve,reject)=>{child.once('spawn',resolve);child.once('error',reject);});child.unref();return {launched:true,shell};
  }
  /** Read Git effective configuration without disclosing proxy credentials to the UI. */
  async probe(workdir){
    const cwd=workdir||process.cwd();
    let git={available:false,proxyConfigured:false};
    try{const {stdout}=await run('git',['--version'],{timeout:5000,cwd,windowsHide:true,maxBuffer:16384,env:parentEnv()});git={available:true,version:stdout.trim()};
      try{const cfg=await run('git',['config','--get-urlmatch','http.proxy','https://github.com/'],{timeout:5000,cwd,windowsHide:true,maxBuffer:16384,env:parentEnv()});git.proxyConfigured=!!cfg.stdout.trim();}catch{}
    }catch{}
    return {git,gateway:!!this.server,automaticCommands:false,automaticReason:'HOST_EXECUTION_ADAPTER_REQUIRED',ssh:'SEPARATE_ADAPTER_REQUIRED',activeSessionScripts:this.sessions.length};
  }
  async testGit(workdir){
    const env={...parentEnv(),...this.environment(),GIT_TERMINAL_PROMPT:'0'};
    try{await run('git',['-c',`http.proxy=${this.url}`,'ls-remote','https://github.com/octocat/Hello-World.git','HEAD'],{cwd:workdir||process.cwd(),env,timeout:20000,maxBuffer:65536,windowsHide:true});return {ok:true,protocol:'https',target:'github.com',operation:'ls-remote'};}
    catch(e){return {ok:false,protocol:'https',target:'github.com',code:e.killed?'COMMAND_TIMEOUT':Number.isInteger(e.code)?'GIT_REQUEST_FAILED':errorCode(e)};}
  }
  async dispose(){
    for(const s of this.sockets)s.destroy();this.sockets.clear();const server=this.server;this.server=null;
    if(server)await new Promise(resolve=>server.close(resolve));
    await Promise.allSettled(this.sessions.map(f=>rm(f,{force:true})));this.sessions=[];
  }
}
