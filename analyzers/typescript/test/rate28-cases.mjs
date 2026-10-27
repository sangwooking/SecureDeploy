// Frozen before implementation. Authored Grade B controls, not independent app truth.
const work="fs.writeFileSync('/owned/state',req.body.value);res.json({ok:true});";
const packet=(setup,body=work,tail='')=>({files:[{filePath:'server.cjs',content:`const app=require('express')();const rateLimit=require('express-rate-limit');const fs=require('fs');${setup}app.post('/work',(req,res)=>{${body}});${tail}`}],nodeManifests:[{filePath:'package.json',express:'4.18.0','express-rate-limit':'7.5.0'}]});
const mount=options=>`app.use(rateLimit(${options}));`;
export const rate28Cases=[];
const add=(id,truth,input,reason)=>rate28Cases.push({id,truth,input,reason,grade:'B_SAME_AUTHOR_NONBLIND'});
for(const [id,setup,tail,reason]of [
 ['always-skip',mount('{limit:3,skip:()=>true}'),'','Explicit skip bypass before a supported state change'],
 ['next-handler',mount('{limit:3,handler:(req,res,next)=>next()}'),'','Exceeded handler explicitly continues to work'],
 ['changed-before',"const opts={limit:3};opts.skip=()=>true;app.use(rateLimit(opts));",'','Changed setting before factory disables limiter'],
 ['other-route',"app.use('/other',rateLimit({limit:3}));",'','Closed control requires work route protection, policy is elsewhere'],
 ['too-late','',mount('{limit:3}'),'Closed control requires protection before work, later registration cannot provide it'],
 ['conditional',mount('{limit:3,skip:req=>req.body.skip}'),'','Closed control assumes attacker chooses skip; general predicate may be unsupported'],
 ['header-key',mount("{limit:3,keyGenerator:req=>req.get('x-forwarded-for')}"),'','Closed control stipulates no trusted proxy sanitization; runtime dimension unknown'],
])add(id,'RISK',packet(setup,work,tail),reason);
const upstash=body=>({files:[{filePath:'app/api/work/route.ts',content:`import {Ratelimit} from '@upstash/ratelimit';import {Redis} from '@upstash/redis';const limiter=new Ratelimit({redis:Redis.fromEnv(),limiter:Ratelimit.slidingWindow(3,'1 m')});export async function POST(request){${body}}`}],nodeManifests:[{filePath:'package.json',next:'15.3.0','@upstash/ratelimit':'2.0.5','@upstash/redis':'1.34.0'}]});
for(const [id,body,reason]of [
 ['upstash-ignored',"await limiter.limit('owned');await fetch('https://api.example.invalid/work',{method:'POST'});return Response.json({ok:true});",'Result ignored before external operation in a closed control'],
 ['upstash-inverted',"const result=await limiter.limit('owned');if(result.success)return new Response('blocked',{status:429});await fetch('https://api.example.invalid/work',{method:'POST'});return Response.json({ok:true});",'Inverted success exit in closed control'],
 ['upstash-stale',"const stale=previousResult;if(!stale.success)return new Response('blocked',{status:429});await limiter.limit('owned');await fetch('https://api.example.invalid/work',{method:'POST'});return Response.json({ok:true});",'A different request result cannot establish this request permission'],
])add(id,'RISK',upstash(body),reason);
for(const [id,setup,body,reason]of [
 ['default',mount('{limit:3}'),work,'Pinned default exceeded handler ends response; not full abuse prevention'],
 ['route','',work,'Route-local middleware is before supported work'],
 ['global',mount("{limit:3,keyGenerator:()=> 'global-owned-budget'}"),work,'Intentional global budget is not a per-user policy'],
 ['max-alias',mount('{max:3}'),work,'Pinned v7 retains max alias'],
 ['zero-blocks',mount('{limit:0}'),work,'Pinned v7 zero blocks, never means unlimited'],
 ['prefix-scope',"app.use('/work',rateLimit({limit:3}));",work,'Exact component path scope applies'],
 ['named',"const {rateLimit:make}=require('express-rate-limit');app.use(make({limit:3}));",work,'Proven named export, not name-only inference'],
 ['multiple',mount('{limit:3}')+mount('{limit:10}'),work,'Valid composition in closed control, combined effects may be unknown'],
 ['public-none','',"res.json({public:true});",'Public low-cost endpoint, no limiter is not automatically a defect'],
 ['custom-handler',mount("{limit:3,handler:(req,res)=>res.status(429).end()}"),work,'Stipulated valid custom handler; general callback contract may be unknown'],
]){
 let input=packet(setup,body);if(id==='route')input.files[0].content=input.files[0].content.replace("app.post('/work',","app.post('/work',rateLimit({limit:3}),");
 add(id,'NORMAL',input,reason);
}
for(const [id,setup,body,reason]of [
 ['external-waf','',work,'External gateway policy not in source'],
 ['dynamic-options',"app.use(rateLimit(externalOptions));",work,'Dynamic options unknown'],
 ['custom-store',mount('{limit:3,store:externalStore}'),work,'Store behavior and connectivity unknown'],
 ['dynamic-limit',mount('{limit:()=>externalLimit}'),work,'Dynamic limit and business budget unknown'],
 ['custom-middleware',mount('{limit:3}')+'app.use(externalGate);',work,'Unknown middleware may change response or dispatch'],
 ['version','app.use(rateLimit({limit:3}));',work,'Different package version has no supported contract'],
 ['changed-later',"const opts={limit:3};app.use(rateLimit(opts));opts.store=externalStore;",work,'Factory copies scalar options; do not infer effective changed runtime policy'],
 ['proxy',"app.set('trust proxy',true);"+mount('{limit:3}'),work,'Proxy hops and header overwrite unknown'],
 ['identity',mount('{limit:3,keyGenerator:req=>req.user.id}'),work,'Actual user identity and auth middleware unknown'],
 ['skip-dynamic',mount('{limit:3,skip:externalSkip}'),work,'External skip decision unknown'],
 ['fail-open',mount('{limit:3,passOnStoreError:true}'),work,'Declared error policy, store outage and business acceptability unknown'],
 ['business-budget',mount('{limit:3}'),"externalBusiness(req);res.json({ok:true});",'Business meaning, actual cost and allowed frequency unknown'],
]){
 const input=packet(setup,body);if(id==='version')input.nodeManifests[0]['express-rate-limit']='6.11.2';
 add(id,'UNKNOWN',input,reason);
}
