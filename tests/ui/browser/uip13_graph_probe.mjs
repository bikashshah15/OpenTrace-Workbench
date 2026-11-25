// UIP-13 graph correction (test harness only; no product behaviour). In-page probe scripts (strings) shared by the library smoke and the product battery.
// HOOK is PASSIVE: it records and calls through. It is installed with Page.addScriptToEvaluateOnNewDocument BEFORE any product script, so graph creation, every
// renderer destroy, every keeper re-parent and every paint root write are captured with a shared sequence counter (ordering reconstructable) and a stack.
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CHROME, connect } from './cdp.mjs';

export const HOOK = `(()=>{ if(window.__gl) return;
 const G=window.__gl={seq:0,ev:[],insts:[],ids:0,mos:new Set(),inCall:0,errors:[],raf:0};
 const now=()=>Math.round(performance.now()*10)/10;
 const log=(k,o)=>{ G.ev.push(Object.assign({seq:++G.seq,t:now(),k},o||{})); if(G.ev.length>6000) G.ev.shift(); };
 const stk=()=>String(new Error().stack).split('\\n').slice(2,11).map((s)=>s.trim().replace(/https?:\\/\\/[^/ )]+/g,'').replace(/file:\\/\\/[^ )]*\\//g,'')).join(' <- ');
 const nid=(o,p)=>{ if(!o) return null; if(!o.__gid) o.__gid=p+(++G.ids); return o.__gid; };
 G.nid=nid; G.log=log;
 const tick=()=>{ G.raf++; requestAnimationFrame(tick); }; requestAnimationFrame(tick);
 // keeper re-parent (app.js paint(): ph.replaceWith(old))
 const rw=Element.prototype.replaceWith; Element.prototype.replaceWith=function(...a){ const n=a[0]; try{ if(n&&n.getAttribute&&n.getAttribute('data-keep')!==null){ const op=n.parentNode;
   log('keep-reparent',{keep:n.getAttribute('data-keep'),host:nid(n,'h'),oldParent:nid(op,'p'),oldParentConnected:op?op.isConnected:null,hostConnectedBefore:n.isConnected}); } }catch(e){ G.errors.push(String(e)); } return rw.apply(this,a); };
 // paint root writes (app.js paint(): el.innerHTML = html) and the navigation clear
 const d=Object.getOwnPropertyDescriptor(Element.prototype,'innerHTML'); Object.defineProperty(Element.prototype,'innerHTML',{configurable:true,enumerable:d.enumerable,get:d.get,set(v){ try{ if(this.id&&/^ot-/.test(this.id)) log('root-innerHTML',{root:this.id,len:String(v).length}); }catch{} return d.set.call(this,v); }});
 // live MutationObserver accounting (duplicate observers / leaks)
 const mo=window.MutationObserver.prototype; const o0=mo.observe, d0=mo.disconnect;
 mo.observe=function(t,opt){ (this.__t=this.__t||[]).push(t); G.mos.add(this); return o0.call(this,t,opt); }; mo.disconnect=function(){ this.__t=[]; return d0.call(this); };
 const inst=(cy,opts)=>{ const cont=opts.container; const id='cy'+(++G.ids); const rec={id,host:nid(cont,'h'),observedParent:cont.parentNode,onCalls:{},destroys:[],mounts:0,cy};
   G.insts.push(rec); cy.__gid=id; nid(cont.parentNode,'p');
   log('cy-create',{inst:id,host:rec.host,hostConnected:!!cont.isConnected,parentConnected:!!(cont.parentNode&&cont.parentNode.isConnected),parent:nid(cont.parentNode,'p')});
   const wrapR=(R)=>{ if(!R||R.__gw) return; R.__gw=1; const dd=R.destroy; R.destroy=function(...a){ const c=cy.container&&cy.container();
     log('renderer-destroy',{inst:id,host:nid(c,'h'),hostConnected:!!(c&&c.isConnected),coreDestroyed:cy.destroyed(),already:!!R.destroyed,viaCyCall:G.inCall>0,hostParent:nid(c&&c.parentNode,'p'),observedParent:nid(rec.observedParent,'p'),stack:stk()});
     rec.destroys.push({seq:G.seq,viaCyCall:G.inCall>0}); return dd.apply(this,a); }; };
   wrapR(cy.renderer());
   for(const m of ['destroy','mount','unmount','destroyRenderer']){ const f=cy[m]; if(typeof f!=='function') continue; cy[m]=function(...a){ log('cy-'+m,{inst:id,stack:stk()}); G.inCall++;
     try{ const r=f.apply(this,a); if(m==='mount'){ rec.mounts++; const c2=cy.container(); rec.observedParent=c2&&c2.parentNode; nid(rec.observedParent,'p'); wrapR(cy.renderer()); } return r; } finally{ G.inCall--; } }; }
   const on=cy.on; cy.on=function(...a){ const key=typeof a[0]==='string'?a[0]+(typeof a[1]==='string'?':'+a[1]:''):'?'; rec.onCalls[key]=(rec.onCalls[key]||0)+1; return on.apply(this,a); };
   const po=new window.MutationObserver((ms)=>{ for(const m of ms) for(const n of m.removedNodes) if(n===cont) log('observed-parent-removal',{inst:id,host:nid(cont,'h'),hostConnectedNow:cont.isConnected}); });
   po.__probe=1; po.observe(cont.parentNode,{childList:true}); };
 let real; const wrap=(f)=>{ const w=function(...a){ const cy=f.apply(this,a); try{ if(a[0]&&a[0].container) inst(cy,a[0]); }catch(e){ G.errors.push('inst:'+String(e)); } return cy; };
   Object.setPrototypeOf(w,f); for(const k of Object.getOwnPropertyNames(f)){ if(!['length','name','prototype','caller','arguments'].includes(k)) try{ w[k]=f[k]; }catch{} } w.__gw=1; return w; };
 Object.defineProperty(window,'cytoscape',{configurable:true,get(){return real;},set(v){ real=(typeof v==='function'&&!v.__gw)?wrap(v):v; }});
})()`;

// Whole-page graph lifecycle summary: per instance destroys (intentional = through a cy.destroy/mount/unmount/destroyRenderer call), live-but-detached instances, live observers.
export const SUMMARY = `(()=>{ const G=window.__gl; const tr=(f,x='n/a')=>{try{return f();}catch{return x;}};
 const insts=G.insts.map((r)=>({id:r.id,host:r.host,mounts:r.mounts,on:r.onCalls,coreDestroyed:tr(()=>r.cy.destroyed()),hostConnected:tr(()=>!!(r.cy.container()&&r.cy.container().isConnected)),
   rendererDestroyed:tr(()=>!!r.cy.renderer().destroyed),listeners:tr(()=>r.cy._private.emitter.listeners.length),destroys:r.destroys}));
 const live=insts.filter((i)=>i.coreDestroyed===false);
 const obs={docEl:0,hostObs:0,parentObs:0,other:0}; for(const m of G.mos){ if(m.__probe||!m.__t||!m.__t.length) continue; for(const t of m.__t){ if(t===document.documentElement) obs.docEl++; else if(t.__gid&&t.__gid[0]==='h') obs.hostObs++; else if(t.__gid&&t.__gid[0]==='p') obs.parentObs++; else obs.other++; } }
 return {insts,liveCount:live.length,liveDetached:live.filter((i)=>!i.hostConnected).length,unintentionalDestroys:insts.reduce((n,i)=>n+i.destroys.filter((d)=>!d.viaCyCall).length,0),obs,raf:G.raf,hookErrors:G.errors.slice(0,5),nEvents:G.ev.length}; })()`;

// One sample of the page + graph host selected by sel. withInk reads canvas alpha>0 pixels on every layer and edge-midpoint ink.
export const SAMPLE = `((sel,withInk)=>{ const G=window.__gl; const tr=(f,x='ERR')=>{try{return f();}catch(e){return x;}};
 const o={t:Math.round(performance.now()),vs:document.visibilityState,focus:document.hasFocus(),raf:G.raf,dpr:devicePixelRatio,inner:[innerWidth,innerHeight]};
 const host=document.querySelector(sel); if(!host){ o.host=null; return o; }
 const r=host.getBoundingClientRect(); o.host={id:G.nid(host,'h'),connected:host.isConnected,rect:[Math.round(r.x),Math.round(r.y),Math.round(r.width),Math.round(r.height)],keep:host.getAttribute('data-keep')};
 const cv=[...host.querySelectorAll('canvas')]; o.canvases=cv.map((c)=>[c.width,c.height,c.clientWidth,c.clientHeight]); const cy=host._cy; if(!cy){ o.cy=null; return o; }
 const ns=cy.nodes(); const pos=ns.map((n)=>n.position()); const rp=ns.map((n)=>n.renderedPosition()); const g=(window.__otStore.get().bom8||{}).graph||{};
 o.cy={id:cy.__gid,destroyed:tr(()=>cy.destroyed()),container:tr(()=>cy.container()===host),rendererDestroyed:tr(()=>!!cy.renderer().destroyed),batching:tr(()=>cy.batching()),nodes:ns.length,edges:cy.edges().length,
   expectedNodes:(g.nodes||[]).length,expectedEdges:(g.edges||[]).length,finite:pos.every((p)=>Number.isFinite(p.x)&&Number.isFinite(p.y))&&rp.every((p)=>Number.isFinite(p.x)&&Number.isFinite(p.y)),
   distinct:new Set(pos.map((p)=>Math.round(p.x)+','+Math.round(p.y))).size,inside:rp.filter((p)=>p.x>=0&&p.x<=r.width&&p.y>=0&&p.y<=r.height).length,zoom:tr(()=>cy.zoom()),pan:tr(()=>cy.pan()),
   selected:cy.$(':selected').map((n)=>n.id()),nodeIds:ns.map((n)=>n.id()),rendered:rp.map((p)=>[Math.round(p.x),Math.round(p.y)])};
 if(withInk){ let ink=0; const pr=devicePixelRatio||1; o.layers=cv.map((c)=>{ try{ const d=c.getContext('2d').getImageData(0,0,c.width,c.height).data; let k=0; for(let i=3;i<d.length;i+=4) if(d[i]>0) k++; ink+=k; return k; }catch(e){ return 'err'; } }); o.ink=ink;
   let eInk=0; const em=cy.edges().map((e)=>e.renderedMidpoint()); for(const m of em){ let hit=false; for(const c of cv){ try{ const x=Math.max(0,Math.round(m.x*pr)-4),y=Math.max(0,Math.round(m.y*pr)-4); const d=c.getContext('2d').getImageData(x,y,9,9).data; for(let i=3;i<d.length;i+=4) if(d[i]>0){hit=true;break;} }catch{} if(hit) break; } if(hit) eInk++; }
   o.edgesWithInk=eInk; }
 return o; })`;

export const ANALYZE = (b64) => `new Promise((res)=>{ const im=new Image(); im.onload=()=>{ const c=document.createElement('canvas'); c.width=im.width; c.height=im.height; const g=c.getContext('2d'); g.drawImage(im,0,0); const d=g.getImageData(0,0,c.width,c.height).data;
 const m=new Map(); for(let i=0;i<d.length;i+=4){ const k=((d[i]>>4)<<8)|((d[i+1]>>4)<<4)|(d[i+2]>>4); m.set(k,(m.get(k)||0)+1); } let top=0; for(const v of m.values()) top=Math.max(top,v);
 res({w:c.width,h:c.height,distinctColours:m.size,nonDominantShare:+(1-top/(d.length/4)).toFixed(4)}); }; im.onerror=()=>res({err:'decode'}); im.src='data:image/png;base64,${b64}'; })`;

export const selftest = () => { for (const [n, s] of [['HOOK', HOOK], ['SUMMARY', SUMMARY], ['SAMPLE', SAMPLE], ['ANALYZE', ANALYZE('AAAA')]]) { try { new Function('return ' + s); } catch (e) { return `${n}: ${e.message}`; } } return null; };

// Visible, foreground desktop Chrome (no --headless, no --disable-gpu), fresh profile = cookie isolation. Returns the flags actually used (profile path redacted).
export async function launchHeaded({ onPid } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'ot-chrome-headed-'));
  const args = [`--user-data-dir=${dir}`, '--no-first-run', '--no-default-browser-check', '--remote-debugging-port=0', '--window-size=1366,900', '--window-position=40,40', 'about:blank'];
  const proc = spawn(CHROME, args, { stdio: ['ignore', 'ignore', 'pipe'] }); onPid && onPid(proc.pid);
  const wsUrl = await new Promise((resolve, reject) => { let buf = ''; const t = setTimeout(() => reject(new Error('chrome did not start')), 25000);
    proc.stderr.on('data', (d) => { buf += d; const m = buf.match(/DevTools listening on (ws:\/\/\S+)/); if (m) { clearTimeout(t); resolve(m[1]); } }); proc.on('exit', () => reject(new Error('chrome exited'))); });
  const browser = await connect(wsUrl);
  const close = async () => { try { browser.close(); } catch {} proc.kill('SIGKILL'); try { rmSync(dir, { recursive: true, force: true }); } catch {} };
  return { browser, close, proc, dir, flags: args.map((a) => a.replace(dir, '<fresh-profile-dir>')) };
}
