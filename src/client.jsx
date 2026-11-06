import React from 'react';
import { App, Boundary, Icon } from './ui.jsx';
import css from './styles.css';
const NS='local-network-assistant';
export const inject=['slots','locale','layout','configForms','connection'];

function Settings({usePreferences,form,open}){
  const state=usePreferences(s=>s),[busy,setBusy]=React.useState(false),[error,setError]=React.useState('');
  return <section className="na-app"><div className="np-main"><h2>网络助手</h2><p className="np-help">模型路由、受管终端与本机代理规则。</p><label className="np-checklabel"><input type="checkbox" disabled={busy||!state.writable||!state.value} checked={state.value?.showSidebar!==false} onChange={async e=>{setBusy(true);setError('');try{if(!await form.set('showSidebar',e.target.checked))setError('设置已变化，请重试。');}catch{setError('设置未保存。');}finally{setBusy(false);}}}/>在侧栏显示入口</label><button className="np-button np-primary" onClick={open}>打开网络助手</button>{error?<p role="alert">{error}</p>:null}</div></section>;
}

/** UI contains no local demo store: every operation calls the owner-restricted Host service. */
export function apply(ctx){
  ctx.effect(()=>ctx.locale.register(NS,{zh:{title:'网络助手'},en:{title:'Network Assistant'}}));
  ctx.effect(()=>{const style=document.createElement('style');style.textContent=css;style.dataset.networkAssistant='';document.head.append(style);return()=>style.remove();});
  const form=ctx.configForms.get(NS);
  const api=async(method,args={},signal)=>{const result=await ctx.connection.rpc.call('/api',`networkAssistant/${method}`,{args},signal);if(!result.ok)throw new Error(result.error?.message||result.error?.code||'RPC_FAILED');return result.value;};
  ctx.slots.inject('main',()=>ctx.slots.register({name:'main',key:NS,locale:NS,inject:()=>({api})},props=><Boundary><App {...props}/></Boundary>));
  ctx.slots.inject('settings.section',()=>ctx.slots.register({name:'settings.section',id:NS,order:82,label:()=>ctx.locale.bind(NS)('title'),locale:NS,inject:()=>({hooks:{preferences:form},form})},props=><Boundary><Settings {...props} open={()=>{props.close();ctx.layout.selectPanel(NS);}}/></Boundary>));
  let sidebar;ctx.effect(()=>{const reconcile=()=>{const value=form.getSnapshot().value;if(!value)return;if(value.showSidebar!==false&&!sidebar)sidebar=ctx.slots.inject('sidebar.panellist',()=>ctx.slots.register({name:'sidebar.panellist',id:NS,order:-3,label:()=>ctx.locale.bind(NS)('title'),locale:NS},({size})=><Icon size={size}/>));if(value.showSidebar===false&&sidebar){sidebar();sidebar=null;}};const unsubscribe=form.subscribe(reconcile);reconcile();return()=>{unsubscribe();sidebar?.();};});
}
