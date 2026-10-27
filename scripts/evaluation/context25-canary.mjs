// Owned canaries only. Never import or execute acquired project sources.
import {createServer,get} from 'node:http';
import {execFileSync} from 'node:child_process';
import assert from 'node:assert/strict';
const hits={a:0,b:0};
const make=name=>createServer((req,res)=>{hits[name]++;res.end(name);});
const a=make('a'),b=make('b');
const start=s=>new Promise((ok,fail)=>{s.once('error',fail);s.listen(0,'127.0.0.1',ok);});
const read=url=>new Promise((ok,fail)=>{
 const req=get(url,res=>{let body='';res.on('data',c=>body+=c);res.on('end',()=>ok(body));});
 req.setTimeout(1000,()=>req.destroy(Error('CANARY_TIMEOUT')));req.on('error',fail);
});
try{
 await start(a);await start(b);
 const base=`http://127.0.0.1:${a.address().port}/`,other=`http://127.0.0.1:${b.address().port}/`;
 assert.equal(await read(new URL(other,base)),'b');
 const prefix='http://a.example.invalid';
 assert.ok('http://a.example.invalid.other.invalid/'.startsWith(prefix));
 assert.notEqual(new URL('http://a.example.invalid.other.invalid/').hostname,new URL(prefix).hostname);
 const changed=new URL(base);assert.equal(changed.hostname,'127.0.0.1');changed.href=other;
 assert.equal(await read(changed),'b');
 assert.equal(await read({hostname:'127.0.0.1',port:b.address().port,path:'/'}),'b');
 const fixed=token=>{if(token!=='approved')throw Error('DESTINATION_REJECTED');return new URL(base);};
 assert.throws(()=>fixed(other),/DESTINATION_REJECTED/);
 assert.equal(await read(fixed('approved')),'a');
 assert.deepEqual(hits,{a:1,b:3});
 console.log(JSON.stringify({ssrf:{absoluteInputReplacedBase:true,prefixIsNotHostCheck:true,hrefMutationChangesTarget:true,optionsAndCallbackSendRequest:true,unapprovedTokenRejected:true,normalTargetPreserved:true,hits}}));
}finally{await new Promise(ok=>a.close(ok));await new Promise(ok=>b.close(ok));}
if(process.argv[2]){
 const html=`<!doctype html><div id="box"></div><script>
 const box=document.getElementById('box');
 const payload='<button onclick="window.canary=1">content</button>';
 box.innerHTML=payload;box.querySelector('button').click();const before=window.canary===1;
 window.canary=0;box.textContent=payload;box.click();
 const after=window.canary===0&&!box.querySelector('button')&&box.textContent===payload;
 document.body.dataset.result=before&&after?'OWNED_CANARY_PASS':'FAIL';
 </script>`;
 const result=execFileSync(process.argv[2],['--headless','--disable-gpu','--no-sandbox','--disable-background-networking','--dump-dom',
  'data:text/html,'+encodeURIComponent(html)],{timeout:15000,maxBuffer:100000,encoding:'utf8',stdio:['ignore','pipe','pipe']});
 assert.match(result,/data-result="OWNED_CANARY_PASS"/);
 console.log(JSON.stringify({xss:{ownedDomExecutedBefore:true,textContentPreservedLiteralAfter:true,reactOrTargetRuntimeVerified:false}}));
}
