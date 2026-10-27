// Owned HTTP control, not express-rate-limit/Upstash execution or a target exploit.
import http from 'node:http';
import assert from 'node:assert/strict';
let now=0,work=0,broken=false,outage=false;const buckets=new Map();
function limit(key){
 if(outage)throw Error('OWNED_FAKE_STORE_FAILURE');
 let b=buckets.get(key);if(!b||now>=b.reset){b={hits:0,reset:now+1000};buckets.set(key,b);}return ++b.hits<=2;
}
const server=http.createServer((req,res)=>{
 const key=req.headers['x-owned-user'];if(!['A','B'].includes(key)){res.writeHead(400);res.end();return;}
 let success;try{success=limit(key);}catch{
  if(req.url==='/fail-open')success=true;else{res.writeHead(503);res.end('owned store failure');return;}
 }
 if(!success&&!broken){res.writeHead(429);res.end('owned limit');return;}
 work++;res.writeHead(200);res.end('owned work');
});
let requests=0;const checks=[];const check=(name,ok)=>{assert.ok(ok,name);checks.push(name);};
try{
 await new Promise(r=>server.listen(0,'127.0.0.1',r));const origin='http://127.0.0.1:'+server.address().port;
 const request=async(user,path='/')=>{assert.ok(++requests<=20);const r=await fetch(origin+path,{method:'POST',headers:{'x-owned-user':user}});await r.text();return r.status;};
 check('A first request',await request('A')===200);check('A within budget',await request('A')===200);
 const before=work;check('A over budget',await request('A')===429);check('blocked request does not run work',work===before);
 check('B independent budget',await request('B')===200);
 now=1000;check('fake clock window reset',await request('A')===200);
 check('normal work retained',work===4);
 outage=true;const start=work;check('store fail closed',await request('A')===503);check('failed store did not run work',start===work);
 check('declared fail open',await request('A','/fail-open')===200);
 outage=false;broken=true;check('broken handler within budget',await request('A')===200);
 const brokenBefore=work;check('broken exceeded handler continues',await request('A')===200);check('bypass performs work',work===brokenBefore+1);
 broken=false;const fixedBefore=work;check('fixed exceeded handler stops',await request('A')===429);check('fixed path preserves work counter',fixedBefore===work);
 console.log(JSON.stringify({checks:checks.length,passed:checks,requests,workExecutions:work,fakeClock:true,fakeStore:true,targetExecuted:false,realLimiterPackageExecuted:false,paidApiCalls:0,distributedRuntimeVerified:false}));
}finally{server.closeAllConnections();await new Promise(r=>server.close(r));}
