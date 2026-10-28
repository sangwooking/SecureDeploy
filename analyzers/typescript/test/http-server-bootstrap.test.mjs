import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../analyzer.mjs';

const sink=`app.post('/',(req,res)=>eval(req.body.value));`;
const run=(adapter,extra='',limits)=>analyze({files:[{filePath:'boot.js',content:
  `const express=require('express');const app=express();${extra}${adapter};${sink}`} ]},limits);
const flow=r=>r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW'&&f.confidence==='HIGH');

for(const adapter of [
  `new (require('http').Server)(app)`,
  `require('http').Server(app)`,
  `new (require('node:http').Server)(app).listen(0)`,
  `new Server(app)`,
])test(`verified http.Server listener retains the same app: ${adapter}`,()=>{
  const r=run(adapter,`const {Server}=require('http');`);
  assert.equal(flow(r).length,1);
  assert.ok(r.files[0].limitations.includes('NODE_HTTP_SERVER_APP_LISTENER_LINK'));
  assert.equal(flow(r)[0].source.kind,'EXPRESS_BODY');
  assert.equal(flow(r)[0].sink.kind,'EVAL_CALL');
  assert.equal(flow(r)[0].disposition,'REVIEW_REQUIRED');
});

test('default ESM HTTP import uses the same listener identity contract',()=>{
  const r=analyze({files:[{filePath:'boot.mjs',content:
    `import http from 'node:http';import express from 'express';const app=express();new http.Server(app);${sink}`} ]});
  assert.equal(flow(r).length,1);
});

for(const [adapter,extra]of [
  [`new (require('https').Server)(app)`,``],
  [`new (require('http').Server)({},app)`,``],
  [`new (require('http').Server)(app,unknown)`,``],
  [`new (require('other').Server)(app)`,``],
  [`new Server(app)`,`const Server=unknown;`],
  [`new http.Server(app)`,`const http=require('http');http.Server=unknown;`],
  [`new http.Server(app)`,`const http=require('http');http.Server.prototype.emit=unknown;`],
  [`new http.Server(app)`,`const http=require('http');const proto=http.Server.prototype;proto.emit=unknown;`],
  [`new http.Server(app)`,`const http=require('http');http.Server.prototype.extra.emit=unknown;`],
  [`new Server(app)`,`const http=require('http');const Server=http.Server;http.Server=unknown;`],
  [`new http.Server(app)`,`const http={Server:unknown};`],
])test(`unverified Server contract cannot retain an app: ${adapter} ${extra}`,()=>{
  const r=run(adapter,extra);assert.equal(flow(r).length,0);
  assert.ok(!r.files[0].limitations.includes('NODE_HTTP_SERVER_APP_LISTENER_LINK'));
});

test('HTTP listener does not activate events or unmounted routers',()=>{
  for(const code of [
    `const router=express.Router();router.post('/',(req,res)=>eval(req.body.value));`,
    `server.on('ready',()=>{${sink}});`,
    `Promise.resolve().then(()=>{${sink}});`,
  ]){
    const r=analyze({files:[{filePath:'boot.js',content:
      `const express=require('express');const app=express();const server=new (require('http').Server)(app);${code}`} ]});
    assert.equal(flow(r).length,0);
  }
});

test('listener app identities, static protection and budgets stay separate',()=>{
  const r=analyze({files:[{filePath:'boot.js',content:`const express=require('express');
    const app=express(),other=express();new (require('http').Server)(app);
    unknown(other);${sink}other.post('/',(req,res)=>eval(req.body.other));`} ]});
  assert.equal(flow(r).length,1);
  const normal=analyze({files:[{filePath:'boot.js',content:`const express=require('express');
    const app=express();new (require('http').Server)(app);${sink.replace('req.body.value','1')}`} ]});
  assert.equal(normal.files[0].entrypoints,1);assert.equal(flow(normal).length,0);
  assert.equal(flow(run(`new (require('http').Server)(app)`,'',{maxSteps:15})).length,0);
});
