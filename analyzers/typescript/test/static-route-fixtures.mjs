// Grade B controls fixed before the evaluation-only candidate implementation.
const router=`const express=require('express');const router=express.Router();`;
const c=(id,content,category,findings,extra={})=>({id,category,findings,input:{files:[{filePath:'routes.cjs',content}],...extra}});
export const staticRouteCases=[
 c('unmounted-input',router+`router.post('/',(req,res)=>eval(req.body.code));module.exports=router;`,'B',1),
 c('unmounted-helper',router+`const run=require('./helper.cjs');router.post('/',(req,res)=>run(req.body.code));module.exports=router;`,'B',1),
 c('validated-number',router+`router.post('/',(req,res)=>eval(Number(req.body.code)));`,'B',0),
 c('foreign-same-name',`const router={post:external};router.post('/',(req,res)=>eval(req.body.code));`,'NONE',0),
 c('created-only',router+`module.exports=router;`,'NONE',0),
 c('mounted-app',router+`const app=express();router.post('/',(req,res)=>eval(req.body.code));app.use('/api',router);`,'A',0),
 c('other-app-router',router+`const other=express.Router();const app=express();other.post('/',(req,res)=>eval('1'));app.use('/api',other);router.post('/',(req,res)=>eval(req.body.code));`,'B',1),
 c('uncalled-factory',router+`module.exports=()=>{router.post('/',(req,res)=>eval(req.body.code));return router;};`,'C',1),
 c('local-factory-router',`const express=require('express');module.exports=()=>{const router=express.Router();router.post('/',(req,res)=>eval(req.body.code));return router;};`,'NONE',0),
 c('handler-alias-safe',router+`const unsafe=(req,res)=>eval(req.body.code);const safe=(req,res)=>eval('1');const selected=safe;router.post('/',selected);`,'B',0),
 c('dynamic-handler',router+`router.post('/',external);`,'D',0),
 c('middleware-closes',router+`router.post('/',(req,res)=>res.end(),(req,res)=>eval(req.body.code));`,'B',0),
 c('middleware-next',router+`router.post('/',(req,res,next)=>next(),(req,res)=>eval(req.body.code));`,'B',1),
 c('middleware-changes-input',router+`router.post('/',(req,res,next)=>{req.body={code:'1'};next();},(req,res)=>eval(req.body.code));`,'B',0),
 c('no-request-source',router+`router.post('/',(req,res)=>eval('1'));`,'B',0),
 c('receiver-changed',router+`router.post=external;router.post('/',(req,res)=>eval(req.body.code));`,'NONE',0),
 c('shared-handler',router+`const other=express.Router();const handler=(req,res)=>eval(req.body.code);router.post('/one',handler);other.post('/two',handler);`,'B',1),
 c('unverified-import',`const router=require('external-router');router.post('/',(req,res)=>eval(req.body.code));`,'NONE',0),
 c('factory-shadow',router+`module.exports=(router)=>{router.post('/',(req,res)=>eval(req.body.code));};`,'NONE',0),
 c('factory-known-alias',router+`const handler=(req,res)=>eval(req.body.code);module.exports=()=>{router.post('/',handler);return router;};`,'C',1),
 c('error-handler-role',router+`router.post('/',(err,req,res,next)=>eval(req.body.code));`,'B',0),
];
staticRouteCases.find(c=>c.id==='unmounted-helper').input.files.push({filePath:'helper.cjs',content:`module.exports=value=>eval(value);`});
