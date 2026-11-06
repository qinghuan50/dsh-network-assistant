import React from 'react';
import { createRoot } from 'react-dom/client';
import { App, Boundary, Icon } from '../src/ui.jsx';
import css from '../src/styles.css';
const style=document.createElement('style');style.textContent=css;document.head.append(style);
const api=async(method,args={},signal)=>{const res=await fetch('/api',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({method,args}),signal});const data=await res.json();if(!res.ok)throw new Error(data.code||'RPC_FAILED');return data.value;};
createRoot(document.getElementById('root')).render(<div className="dev-shell"><aside><div className="dev-brand"><Icon size={25}/><span>DeepSeek<br/><small>Harness</small></span></div><p>工作区</p><div>对话</div><div>插件</div><p>设置</p><div className="dev-selected"><Icon/>网络助手</div><small className="dev-foot">独立开发预览 · 真实本机后端</small></aside><Boundary><App api={api}/></Boundary></div>);
