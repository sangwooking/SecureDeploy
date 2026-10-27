// Owned loopback HTTP canary. No target application or middleware package is executed.
import http from 'node:http';
import {spawn} from 'node:child_process';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import assert from 'node:assert/strict';
const binary=process.argv[2];if(!binary)throw Error('EXISTING_CHROMIUM_PATH_REQUIRED');
const servers=[];let browser,profile;
async function listen(handler){const s=http.createServer(handler);servers.push(s);await new Promise(r=>s.listen(0,'127.0.0.1',r));return 'http://127.0.0.1:'+s.address().port;}
let trusted,untrusted,changes=0,preflights=0,next=0;const sessions=new Set();
try{
 const api=await listen((req,res)=>{
  const path=req.url,origin=req.headers.origin;
  const id=/ownedSid=(\d+)/.exec(req.headers.cookie??'')?.[1];
  const valid=id&&sessions.has(id);
  const allowed=path==='/reflect'||path==='/preflight'||path==='/bootstrap';
  res.setHeader('Access-Control-Allow-Origin',path==='/wildcard'||path==='/public'?'*':allowed?origin??trusted:trusted);
  res.setHeader('Access-Control-Allow-Credentials','true');
  res.setHeader('Access-Control-Allow-Methods','GET, POST');res.setHeader('Access-Control-Allow-Headers','X-Owned-Test, X-Owned-Token');
  if(req.method==='OPTIONS'){preflights++;res.writeHead(204);res.end();return;}
  if(path==='/bootstrap'||path==='/rotate'){
   if(path==='/rotate'&&!valid){res.writeHead(401);res.end();return;}
   if(id)sessions.delete(id);const newId=String(++next);sessions.add(newId);
   res.setHeader('Set-Cookie',[`ownedSid=${newId}; HttpOnly; SameSite=Lax; Path=/`,'ownedPreference=dark; SameSite=Lax; Path=/']);
  }else if(path==='/logout'){if(id)sessions.delete(id);}
  else if(path==='/who'&&!valid){res.writeHead(401);res.end();return;}
  else if(path==='/unguarded'){changes++;}
  else if(path==='/guarded'){
   if(origin!==trusted||req.headers['x-owned-token']!=='owned-test-nonce'||!valid){res.writeHead(403);res.end();return;}
   changes++;
  }else if(['/reflect','/wildcard','/fixed','/preflight'].includes(path)&&!valid){res.writeHead(401);res.end();return;}
  res.setHeader('Content-Type','application/json');res.end(JSON.stringify({ok:true}));
 });
 const html=origin=>`<!doctype html><script>(async()=>{const api=${JSON.stringify(api)},checks=[];const check=(name,ok)=>checks.push({name,ok:!!ok});
 const f=(p,o={})=>fetch(api+p,{credentials:'include',...o});
 const blocked=async(p,o)=>{try{await f(p,o);return false}catch{return true}};
 try{
 await f('/bootstrap');check('reflected-credential-read',(await f('/reflect')).ok);
 check('wildcard-credential-read-blocked',await blocked('/wildcard'));
 check('public-without-credentials',(await fetch(api+'/public',{credentials:'omit'})).ok);
 check('preflight-and-read',(await f('/preflight',{method:'POST',headers:{'X-Owned-Test':'yes'}})).ok);
 check('fixed-origin-'+(${JSON.stringify(origin)}==='trusted'?'allowed':'blocked'),${JSON.stringify(origin)}==='trusted'?(await f('/fixed')).ok:await blocked('/fixed'));
 if(${JSON.stringify(origin)}==='trusted'){
 check('missing-token-rejected',(await f('/guarded',{method:'POST'})).status===403);
 check('wrong-token-rejected',(await f('/guarded',{method:'POST',headers:{'X-Owned-Token':'wrong'}})).status===403);
 check('valid-token-accepted',(await f('/guarded',{method:'POST',headers:{'X-Owned-Token':'owned-test-nonce'}})).ok);
 check('rotation',(await f('/rotate')).ok);check('rotated-session-usable',(await f('/who')).ok);
 check('httponly-not-script-readable',!document.cookie.includes('ownedSid=')&&document.cookie.includes('ownedPreference='));
 await f('/logout');check('server-invalidation',(await f('/who')).status===401);
 }else{
 check('cors-not-csrf-boundary',await blocked('/unguarded',{method:'POST'}));
 check('untrusted-origin-guard-blocked',await blocked('/guarded',{method:'POST'}));
 }
 }catch{checks.push({name:'unexpected-browser-error',ok:false})}
 await fetch('/done',{method:'POST',body:JSON.stringify(checks)});
 })()</script>`;
 const reports=[];
 const page=kind=>async(req,res)=>{if(req.url==='/done'){let data='';for await(const c of req){data+=c;if(data.length>12000){res.destroy();return;}}reports.push(...JSON.parse(data));res.end('ok');return;}res.setHeader('Content-Type','text/html');res.end(html(kind));};
 untrusted=await listen(page('untrusted'));trusted=await listen(page('trusted'));
 profile=await mkdtemp(join(tmpdir(),'securedeploy-web27-browser-'));
 const launch=async url=>{
  browser=spawn(binary,['--headless','--no-sandbox','--disable-gpu','--disable-background-networking','--no-proxy-server','--user-data-dir='+profile,url],{stdio:'ignore'});
  const child=browser;const error=new Promise((_,reject)=>child.once('error',reject));
  let timer;await Promise.race([new Promise(r=>{const poll=setInterval(()=>{if(reports.some(c=>c.name===(url===trusted?'server-invalidation':'untrusted-origin-guard-blocked'))){clearInterval(poll);r();}},50);timer=setTimeout(()=>{clearInterval(poll);r();},12000);}),error]);
  clearTimeout(timer);child.kill('SIGTERM');await new Promise(r=>child.once('exit',r));browser=undefined;
 };
 await launch(untrusted);assert.equal(changes,1,'cross-origin simple POST changes state despite unreadable response');
 await launch(trusted);assert.equal(changes,2);assert.ok(preflights>=2);
 assert.ok(reports.length>=16);assert.ok(reports.every(c=>c.ok),JSON.stringify(reports));
 console.log(JSON.stringify({passed:reports.length,preflights,ownedStateChanges:changes,crossOriginSameSite:true,tls:false,realMiddlewareExecuted:false,checks:reports}));
}finally{
 if(browser){browser.kill('SIGKILL');await new Promise(r=>browser.once('exit',r));}
 for(const s of servers){s.closeAllConnections();await new Promise(r=>s.close(r));}
 if(profile)await rm(profile,{recursive:true,force:true});
}
