import {createServer} from 'node:http';
import {once} from 'node:events';
import {readFile} from 'node:fs/promises';
import assert from 'node:assert/strict';
import {GET as before} from './before.mjs';
import {GET as after} from './after.mjs';
import {analyze} from '../../analyzer.mjs';

const key='SECUREDEPLOY_SYNTHETIC_LAB_SECRET';
assert.ok(!Object.hasOwn(process.env,key),'ISOLATED_ENVIRONMENT_REQUIRED');
const canary='canary22-owned-local-lab-only';process.env[key]=canary;
const observations=[];
const server=createServer(async(req,res)=>{
  const response=(req.url==='/before'?before:after)();
  res.writeHead(response.status,{'Content-Type':'application/json'});res.end(await response.text());
});
try{
  server.listen(0,'127.0.0.1');await once(server,'listening');
  for(const [name,expected]of [['before',true],['after',false]]){
    const code=await readFile(new URL(name+'.mjs',import.meta.url),'utf8');
    const r=analyze({files:[{filePath:'app/api/check/route.js',content:code}],nodeManifests:[{filePath:'package.json',next:'15.3.0'}]});
    const fs=r.findings.filter(f=>f.ruleId==='TS_SENSITIVE_DATA_EXPOSURE');
    assert.equal(fs.length,expected?1:0);
    const response=await fetch(`http://127.0.0.1:${server.address().port}/${name}`),text=await response.text(),body=JSON.parse(text);
    assert.equal(text.includes(canary),expected);assert.equal(body.status,'ok');assert.equal(response.status,200);
    assert.ok(!JSON.stringify(r).includes(canary));
    observations.push({version:name,staticCandidates:fs.length,canaryInHttpResponse:text.includes(canary),statusPreserved:true,
      parsed:r.files[0].parseStatus,entries:r.files[0].entrypoints,coverage:r.status});
  }
  process.stdout.write(JSON.stringify({grade:'B_AUTHORED_LOCAL_HTTP_NOT_NEXT_DEPLOYMENT',observations,externalSourceExecuted:false,paidAiCalls:0})+'\n');
}finally{
  delete process.env[key];server.closeAllConnections();await new Promise(resolve=>server.close(resolve));
}
