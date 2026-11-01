// Executes only the three owned fixtures beside this script, never submitted project code.
// Usage: node SCRIPT /trusted/express/index.js OUTPUT_JSON
import fs from 'node:fs';import path from 'node:path';import{pathToFileURL}from'node:url';import{createHash}from'node:crypto';import assert from'node:assert/strict';
import{render as before}from'./fixtures/harden01/html-before.mjs';
import{render as broken}from'./fixtures/harden01/html-broken.mjs';
import{render as fixed}from'./fixtures/harden01/html-fixed.mjs';
const[entry,output]=process.argv.slice(2);if(!entry||!output)throw Error('Trusted Express entry and new output path required');
const{default:express}=await import(pathToFileURL(path.resolve(entry)));
const sha=b=>createHash('sha256').update(b).digest('hex'),servers=[],rows=[];
try{
 for(const parser of ['simple','extended']){
  const endpoints=[];
  for(const render of[before,broken,fixed]){
   const app=express();app.set('query parser',parser);app.use((req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
   app.get('/profile',(req,res)=>res.type('html').send(render(req.query.name)));app.get('/health',(req,res)=>res.json({ready:true,count:12}));
   app.use((err,req,res,next)=>res.status(500).json({error:'OWNED_RENDER_FAILURE'}));
   const server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});servers.push(server);endpoints.push(`http://127.0.0.1:${server.address().port}`);
  }
  const normal=['/profile?name=Alice','/profile','/profile?name=A&name=B','/profile?name=','/profile?name=%20%20','/profile?name=Hello%20world','/profile?name='+encodeURIComponent('홍익🙂'),' /profile?name=0123456789'.trim(),'/profile?name='+('A'.repeat(4096)),'/health'];
  // For simple parser, bracket keys remain absent. Extended parser yields an object; both preserve their own prior status.
  const cases=[...normal,'/profile?name[x]=value','/profile?name='+encodeURIComponent('<b data-owned-marker="proof">TEXT</b>'),'/profile?name='+encodeURIComponent('&<>"\'')];
  for(const url of cases){
   const responses=[];for(const base of endpoints){const r=await fetch(base+url);responses.push({status:r.status,body:await r.text(),mime:r.headers.get('content-type')});}
   const securityOutput=url.includes('%3C')||url.includes('%26');const[a,b,c]=responses;
   assert.equal(c.status,a.status,parser+url);if(!securityOutput)assert.equal(c.body,a.body,parser+url);
   if(securityOutput){assert.ok(!c.body.includes('<b data-owned-marker'));assert.ok(c.body.includes('&lt;'));}
   rows.push({parser,input:url.length>180?'LONG_4096':securityOutput?'ENCODED_SPECIAL_OR_HARMLESS_MARKER':url,beforeStatus:a.status,brokenStatus:b.status,fixedStatus:c.status,brokenRegression:b.status!==a.status||!securityOutput&&b.body!==a.body,fixedNormalPreserved:securityOutput?null:c.body===a.body,securityOutputChanged:securityOutput?c.body!==a.body:null,fixedBodySha256:sha(c.body)});
  }
 }
 const report={scope:'Owned Express real loopback HTTP; no external application executed',rows,brokenMissingOrRepeatedRegressions:rows.filter(r=>r.parser==='simple'&&['/profile','/profile?name=A&name=B'].includes(r.input)&&r.brokenRegression).length,fixedRegressions:rows.filter(r=>r.fixedStatus!==r.beforeStatus||r.fixedNormalPreserved===false).length,fixtures:Object.fromEntries(['before','broken','fixed'].map(n=>[n,sha(fs.readFileSync(new URL(`./fixtures/harden01/html-${n}.mjs`,import.meta.url)))]))};
 assert.equal(report.brokenMissingOrRepeatedRegressions,2);assert.equal(report.fixedRegressions,0);fs.writeFileSync(output,JSON.stringify(report,null,2));console.log(JSON.stringify({httpCases:rows.length,oldRegressionsPreserved:2,fixedRegressions:0}));
}finally{await Promise.all(servers.map(s=>new Promise(resolve=>{s.closeAllConnections();s.close(resolve);})));}
