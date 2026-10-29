// Evaluation-only, fixed controls. These strings are parsed, never executed.
import {analyze,VERSION} from '../../analyzers/typescript/analyzer.mjs';

const source = body => [{filePath:'boot.js',content:`const express=require('express');${body}`}];
const handler = `(req,res)=>eval(req.body.value)`;
export const controls = [
  {id:'http-createServer-preserves-app',expect:'FLOW',files:source(`const http=require('http');const app=express();http.createServer(app);app.post('/',${handler});`)},
  {id:'http-Server-constructor-app-escape',expect:'DEFERRED',files:source(`const http=require('http');const app=express();new http.Server(app);app.post('/',${handler});`)},
  {id:'http-Server-call-app-escape',expect:'DEFERRED',files:source(`const {Server}=require('http');const app=express();Server(app);app.post('/',${handler});`)},
  {id:'explicit-local-bootstrap',expect:'FLOW',files:source(`const app=express();function configure(a){a.post('/',${handler});}configure(app);`)},
  {id:'explicit-factory-return',expect:'FLOW',files:source(`function configure(){const router=express.Router();router.post('/',${handler});return router;}const app=express();app.use('/api',configure());`)},
  {id:'function-constructor-bootstrap',expect:'FLOW',files:source(`function Service(){this.app=express();this.app.post('/',${handler});}new Service();`)},
  {id:'class-bootstrap',expect:'DEFERRED',files:source(`class Service{constructor(){this.app=express();}start(){this.app.post('/',${handler});}}const service=new Service();service.start();`)},
  {id:'exported-class-no-caller',expect:'DEFERRED',files:source(`module.exports=class Service{start(){const app=express();app.post('/',${handler});}};`)},
  {id:'promise-completion-bootstrap',expect:'DEFERRED',files:source(`const app=express();function configure(a){a.post('/',${handler});}Promise.resolve().then(()=>configure(app));`)},
  {id:'external-completion-bootstrap',expect:'DEFERRED',files:source(`const app=express();function configure(a){a.post('/',${handler});}unknownReadiness().then(()=>configure(app));`)},
  {id:'database-event-bootstrap',expect:'DEFERRED',files:source(`const app=express();db.on('open',()=>app.post('/',${handler}));`)},
  {id:'static-import-bootstrap',expect:'FLOW',files:[
    {filePath:'entry.mjs',content:`import {configure} from './server.mjs';configure();`},
    {filePath:'server.mjs',content:`import express from 'express';export function configure(){const app=express();app.post('/',${handler});}`},
  ]},
  {id:'dynamic-import-bootstrap',expect:'DEFERRED',files:[
    {filePath:'entry.mjs',content:`import('./server.mjs').then(m=>m.configure());`},
    {filePath:'server.mjs',content:`import express from 'express';export function configure(){const app=express();app.post('/',${handler});}`},
  ]},
  {id:'uninvoked-initializer',expect:'NO_REGISTERED_FLOW',files:source(`function configure(){const app=express();app.post('/',${handler});}`)},
  {id:'unmounted-router',expect:'NO_REGISTERED_FLOW',files:source(`const app=express();const router=express.Router();router.post('/',${handler});`)},
  {id:'unrelated-app-not-a-mount',expect:'NO_REGISTERED_FLOW',files:source(`const first=express(),second=express();const router=express.Router();router.post('/',${handler});second.use('/api',first);`)},
  {id:'terminated-initializer',expect:'NO_REGISTERED_FLOW',files:source(`const app=express();function configure(a){return; a.post('/',${handler});}configure(app);`)},
  {id:'dynamic-registration-target',expect:'DEFERRED',files:source(`const app=express();unknownRegistration(app,${handler});`)},
  {id:'separate-request-inputs',expect:'FLOW',count:1,files:source(`const app=express();app.post('/a',${handler});app.post('/b',(req,res)=>eval('1'));`)},
  {id:'constant-safe-handler',expect:'SAFE_TARGET',files:source(`const app=express();function configure(a){a.post('/',(req,res)=>eval('1'));}configure(app);`)},
  {id:'early-blocked-handler',expect:'SAFE_TARGET',files:source(`const app=express();app.post('/',(req,res)=>{return res.end();eval(req.body.value);});`)},
  {id:'earlier-middleware-terminates',expect:'KNOWN_BLOCKED_REVIEW_CANDIDATE',files:source(`const app=express();app.post('/',(req,res)=>res.end(),${handler});`)},
];

export function evaluateControls() {
  return controls.map(c=>{
    const r=analyze({files:c.files});
    const matching=r.findings.filter(f=>f.ruleId==='JS_EVAL_INPUT_FLOW');
    const listenerVersion=['ts-server-v45','ts-server-v46','ts-server-v47','ts-server-v48'].includes(VERSION);
    const expected=['ts-server-v46','ts-server-v47','ts-server-v48'].includes(VERSION)&&c.id==='earlier-middleware-terminates'?'SAFE_TARGET'
      :['ts-server-v47','ts-server-v48'].includes(VERSION)&&c.id==='class-bootstrap'?'FLOW'
      :listenerVersion&&['http-Server-constructor-app-escape','http-Server-call-app-escape'].includes(c.id)?'FLOW':c.expect;
    return {id:c.id,expected,baselineExpected:c.expect,expectedCount:['FLOW','KNOWN_BLOCKED_REVIEW_CANDIDATE'].includes(expected)?(c.count??1):0,
      observedCount:matching.length,highCount:matching.filter(f=>f.confidence==='HIGH').length,
      entries:r.files.reduce((n,f)=>n+f.entrypoints,0),
      functions:r.files.reduce((n,f)=>n+f.functionsAnalyzed,0),
      limitations:[...new Set(r.files.flatMap(f=>f.limitations))].sort(),
      semantics:'CONTROL_ONLY_NOT_REAL_APP_ACCURACY_OR_MIDDLEWARE_EXECUTION_PROOF'};
  });
}
