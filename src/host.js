import z from '@deepseek-ai/schemastery';
import { Remote, TypertRemoteService, principalOf } from '@deepseek-ai/dsh-typert-protocol';
import { NetworkEngine } from './engine.js';
import { DEFAULTS, fail } from './config.js';
import { candidates } from './detect.js';
import { discoverRuleFiles } from './rule-discovery.js';

const model=z.object({id:z.string(),name:z.string(),contextWindow:z.number(),maxTokens:z.number()});
const channel=z.object({id:z.string(),name:z.string(),baseURL:z.string(),api:z.string(),models:z.array(model)});
export const Config=z.object({
  mode:z.string().default('inherit').volatile(),paused:z.boolean().default(false).volatile(),showSidebar:z.boolean().default(true).volatile(),
  source:z.string().default('system').volatile(),proxyUrl:z.string().default('').volatile(),bypass:z.string().default('').volatile(),terminalEnabled:z.boolean().default(false).volatile(),
  controllerURL:z.string().default(DEFAULTS.controllerURL).volatile(),effectivePath:z.string().default('').volatile(),scriptPath:z.string().default('').volatile(),ruleClient:z.string().default('verge').volatile(),
  corePath:z.string().default('').volatile(),channels:z.array(channel).default([]).volatile(),routes:z.dict(String).default({}).volatile(),tlsCompatOrigins:z.array(String).default([]).volatile(),
});
export const inject=['settings','credentials','llm'];

/** One authenticated owner service; names never collide with legacy modelProxy plugins. */
export function apply(ctx,config){
  ctx.effect(()=>ctx.settings.configure({auto:false},ctx.fiber));
  const engine=new NetworkEngine(ctx,config);
  class NetworkAssistantService extends TypertRemoteService {
    constructor(ctx){super(ctx,'networkAssistant');}
    owner(){if(principalOf(this.ctx.invocation))fail('OWNER_ONLY');}
    @Remote async state(){this.owner();return engine.state();}
    @Remote async saveConfig(draft,revision,secrets){this.owner();return engine.saveConfig(draft,revision,secrets||{});}
    @Remote async saveRoute(origin,mode,revision){this.owner();return engine.saveRoute(origin,mode,revision);}
    @Remote async saveTLSCompatibility(origin,enabled,revision){this.owner();return engine.saveTLSCompatibility(origin,enabled,revision);}
    @Remote async saveChannel(draft,revision,key){this.owner();return engine.saveChannel(draft,revision,key);}
    @Remote async removeChannel(id,revision){this.owner();return engine.removeChannel(id,revision);}
    @Remote async fetchModels(id){this.owner();return engine.fetchModels(id);}
    @Remote async diagnose(id){this.owner();return engine.diagnose(id);}
    @Remote async testChat(id){this.owner();return engine.testChat(id);}
    @Remote async detectProxy(){this.owner();return candidates();}
    @Remote async refreshProxy(){this.owner();return engine.serial(async()=>{await engine.refreshNetwork();return engine.state();});}
    @Remote async terminalProbe(workdir){this.owner();return engine.gateway.probe(workdir);}
    @Remote async terminalTest(workdir){this.owner();if(!engine.value().terminalEnabled)fail('TERMINAL_NOT_ENABLED');return engine.gateway.testGit(workdir);}
    @Remote async terminalOpen(shell){this.owner();if(!engine.value().terminalEnabled)fail('TERMINAL_NOT_ENABLED');return engine.gateway.open(shell);}
    @Remote async terminalScript(shell){this.owner();if(!engine.value().terminalEnabled||!['cmd','pwsh','system'].includes(shell))fail('TERMINAL_NOT_ENABLED');return engine.gateway.script(shell);}
    @Remote async detectRules(){this.owner();return engine.rules.detect();}
    @Remote async discoverRules(){this.owner();return discoverRuleFiles();}
    @Remote async previewRules(options,group){this.owner();return engine.serial(()=>engine.rules.preview({hosts:engine.ruleHosts(options),group}));}
    @Remote async applyRules(id){this.owner();return engine.serial(()=>engine.rules.apply(id));}
    @Remote async undoRules(){this.owner();return engine.serial(()=>engine.rules.undo());}
    @Remote async verifyRules(host){this.owner();if(typeof host!=='string'||host.length>253)fail('INVALID_RULE_HOST');return engine.rules.connections(host);}
    @Remote async startCore(){this.owner();return engine.serial(()=>engine.core.start(engine.value().corePath));}
    @Remote async stopCore(){this.owner();return engine.serial(()=>engine.core.stop());}
    @Remote async refreshCore(){this.owner();return engine.core.refresh();}
    @Remote async selectCore(name){this.owner();return engine.serial(()=>engine.core.select(name));}
  }
  ctx.plugin(NetworkAssistantService);
  ctx.effect(()=>{engine.initialize().catch(e=>ctx.logger?.warn?.('network-assistant: initialize failed %s',e?.code||'INITIALIZE_FAILED'));return ()=>engine.dispose();});
  // The provider directory may register after this plugin. These retries only reconcile
  // model metadata; they never mutate native provider URLs or spawn terminal windows.
  ctx.effect(()=>{const timers=[300,1200,4000].map(ms=>setTimeout(()=>{if(!engine.closed)engine.serial(()=>engine.publish()).catch(()=>{});},ms));return()=>timers.forEach(clearTimeout);});
}
