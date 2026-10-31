// Independent synthetic review oracles; frozen separately from the old 33.
// No private project source or whole-program safety oracle.
const m={filePath:'package.json',moduleType:'module',resolutionStatus:'PARSED',express:'4.21.2',next:'15.3.0'};
const c=(id,truth,files,rule,oracle)=>({id,truth,rule,oracle,input:{files:Object.entries(files).map(([filePath,content])=>({filePath,content})),nodeManifests:[m]}});
const e='JS_EVAL_INPUT_FLOW',s='TS_SENSITIVE_DATA_EXPOSURE';const p="import express from 'express';const app=express();const r=express.Router();";
export const cases=[
 c('mount-two-forwarders',true,{'web.mjs':p+"function pass(req,res,next){next();}r.post('/orders/:item',(req,res)=>eval(req.params.item));app.use('/v1',pass,pass,r);"},e,'Literal router registration; two no-effect callbacks reach eval.'),
 c('mount-nested-arrays',true,{'web.mjs':p+"function forward(req,res,next){next();}r.post('/orders',(req,res)=>eval(req.body.expression));app.use('/v1',[forward,[forward,r]]);"},e,'Direct immutable registration array reaches the registered body sink.'),
 c('router-use-other-path-forwarder',true,{'web.mjs':p+"r.use('/admin',(req,res,next)=>next());r.get('/public',(req,res)=>eval(req.query.code));app.use(r);"},e,'Forwarding middleware on another path is not a protection proof.'),
 c('mount-terminal-deny',false,{'web.mjs':p+"r.get('/order',(req,res)=>eval(req.query.code));app.use('/v1',(req,res,next)=>res.status(403).end(),r);"},e,'Synchronous end before the child router means this registered chain cannot reach sink.'),
 c('mount-fixed-code',false,{'web.mjs':p+"r.get('/order',(req,res)=>eval('1+1'));app.use('/v1',(req,res,next)=>next(),r);"},e,'Registered fixed code does not use request values.'),
 c('mount-conditional-guard',null,{'web.mjs':p+"r.get('/order',(req,res)=>eval(req.query.code));app.use('/v1',(req,res,next)=>{if(req.headers.authorization)next();else res.end();},r);"},e,'Conditional prefix is outside bounded forward-only proof; never infer auth success.'),
 c('unmounted-router',null,{'web.mjs':p+"r.get('/order',(req,res)=>eval(req.query.code));"},e,'No root registration. No endpoint safety claim.'),
 c('dynamic-router',null,{'web.mjs':p+"app.use(loadRoute());"},e,'Unknown callback identity.'),
 c('pages-body-post',true,{'pages/api/order.ts':"export default async function order(req,res){eval(req.body.expression);res.json({ok:true});}"},e,'Pages default async body input reaches eval.'),
 c('pages-src-arrow-header',true,{'src/pages/api/format.jsx':"export default (req,res)=>{eval(req.headers['x-format']);res.end();};"},e,'Default Pages arrow has IncomingMessage header input.'),
 c('pages-three-file-barrel',true,{'pages/api/work.ts':"export {default} from '../../logic/index.ts';",'logic/index.ts':"export {worker as default} from './action.ts';",'logic/action.ts':"export function worker(req,res){eval(req.query.text);res.json({done:true});}"},e,'Two explicit static links retain handler identity and sink file.'),
 c('pages-constant-response',false,{'pages/api/health.js':"export default function health(req,res){res.json({status:'ok'});}"},e,'Registered handler never uses eval.'),
 c('pages-fixed-eval',false,{'pages/api/order.tsx':"export default function order(req,res){eval('2+2');res.end();}"},e,'Actual handler with a constant eval argument.'),
 c('ui-component-not-api',null,{'pages/order.tsx':"export default function Order(props){return <div>{props.title}</div>;}"},e,'UI page is not a request handler.'),
 c('pages-dynamic-wrapper',null,{'pages/api/order.ts':"export default wrap((req,res)=>eval(req.query.text));"},e,'Unknown wrapper is not registered as verified handler.'),
 c('const-nested-key',true,{'web.mjs':p+"app.get('/status',(req,res)=>{const prefix='API';const name=`${prefix}_SECRET`;res.json({ok:true,key:process.env[name]});});"},s,'Closed scalar const and static template key plus actual response.'),
 c('literal-array-key',true,{'web.mjs':p+"app.get('/status',(req,res)=>res.json({key:process.env[['API','SECRET'].join('_')]}));"},s,'Bounded literal array join identifies a secret source and real sink.'),
 c('computed-key-without-sink',false,{'web.mjs':p+"app.get('/status',(req,res)=>{const privateValue=process.env[['API','SECRET'].join('_')];res.json({ok:true});});"},s,'Read alone is not response exposure.'),
 c('computed-public-key',false,{'web.mjs':p+"app.get('/status',(req,res)=>res.json({key:process.env[['SUPABASE','ANON','KEY'].join('_')]}));"},s,'Known publicly intended key is not secret by name alone.'),
 c('mutated-key-array',null,{'web.mjs':p+"app.get('/status',(req,res)=>{const parts=['API','SECRET'];parts[1]=req.query.key;res.json({key:process.env[parts.join('_')]});});"},s,'Mutable array cannot supply static key proof.'),
 c('cyclic-key-binding',null,{'web.mjs':p+"app.get('/status',(req,res)=>{const a=b;const b=a;res.json({key:process.env[a]});});"},s,'TDZ/cycle are not constant key proof.'),
 c('escaped-key-array',null,{'web.mjs':p+"app.get('/status',(req,res)=>{const parts=['API','SECRET'];change(parts);res.json({key:process.env[parts.join('_')]});});"},s,'Array escape could change native join result.'),
];
