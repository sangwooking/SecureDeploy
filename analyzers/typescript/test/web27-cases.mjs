// Frozen authored static contracts, not an independent or deployed-web accuracy oracle.
const code=(setup,body,after='')=>`const app=require('express')();const cors=require('cors');const session=require('express-session');const fs=require('fs');${setup}app.post('/work',(req,res)=>{${body}});${after}`;
const packet=content=>({files:[{filePath:'server.cjs',content}],nodeManifests:[{filePath:'package.json',express:'4.18.0',cors:'2.8.5','express-session':'1.18.1'}]});
const sensitive='res.json({value:process.env.AUTH_TOKEN});';
const readSession='const current=req.session;';
const sess=c=>`app.use(session({secret:process.env.SESSION_SECRET,resave:false,saveUninitialized:false,cookie:${c}}));`;
export const web27Cases=[];
const add=(track,id,truth,input,reason)=>web27Cases.push({track,id:track.toLowerCase()+'-'+id,truth,input,reason,grade:'B_SAME_AUTHOR_NONBLIND'});
for(const [id,truth,setup,body,after,reason]of [
 ['reflect','RISK','app.use(cors({origin:true,credentials:true}));',sensitive,'','Reflected arbitrary origin with credentials at a sensitive response'],
 ['route','RISK','',sensitive,'','Route-local reflection with sensitive response'],
 ['alias','RISK',"const policy={origin:true,credentials:true};app.use(cors(policy));",sensitive,'','Readonly static alias retains policy'],
 ['prefix-scope','RISK',"app.use('/work',cors({origin:true,credentials:true}));",sensitive,'','Mounted policy applies to exact path'],
 ['dynamic-prefix','RISK',"app.use(cors({origin:(o,cb)=>cb(null,o.startsWith('https://trusted.invalid')),credentials:true}));",sensitive,'','Prefix permits a distinct host; callback contract may be unsupported'],
 ['fixed','NORMAL',"app.use(cors({origin:'https://trusted.invalid',credentials:true}));",sensitive,'','Exact configured origin, not arbitrary reflection'],
 ['allowlist','NORMAL',"app.use(cors({origin:['https://a.invalid','https://b.invalid'],credentials:true}));",sensitive,'','Explicit fixed origin list; domain trust still external'],
 ['public','NORMAL',"app.use(cors({origin:'*'}));","res.json({public:true});",'','Public resource without credentials'],
 ['wildcard-credentials','NORMAL',"app.use(cors({origin:'*',credentials:true}));","res.json({public:true});",'','Credentialed reads blocked by browser, not proven disclosure'],
 ['after-route','NORMAL','',sensitive,"app.use(cors({origin:true,credentials:true}));",'Later middleware does not precede this terminal route'],
 ['other-path','NORMAL',"app.use('/other',cors({origin:true,credentials:true}));",sensitive,'','Unrelated mount path'],
 ['opaque','UNKNOWN',"app.use(cors(externalPolicy));",sensitive,'','External policy is not known'],
 ['callback','UNKNOWN',"app.use(cors({origin:externalCheck,credentials:true}));",sensitive,'','External origin decision'],
 ['sensitivity','UNKNOWN',"app.use(cors({origin:true,credentials:true}));","res.json(externalData);",'','Response sensitivity is not established'],
 ['overwrite','UNKNOWN',"const policy={origin:true,credentials:true};app.use(cors(policy));policy.origin=external;",sensitive,'','Later options mutation invalidates earlier proof'],
 ['middleware','UNKNOWN',"app.use(cors({origin:true,credentials:true}));app.use(externalGate);",sensitive,'','Unknown middleware can alter response or terminate path'],
]){
 let input=packet(code(setup,body,after));
 if(id==='route')input=packet(input.files[0].content.replace("app.post('/work',", "app.post('/work',cors({origin:true,credentials:true}),"));
 add('CORS',id,truth,input,reason);
}
for(const [id,truth,setup,body,reason]of [
 ['no-httponly','RISK',sess('{secure:true,httpOnly:false,sameSite:"lax"}'),readSession+'res.json({ok:true});','Proven session cookie explicitly script readable'],
 ['route-session','RISK','',readSession+'res.json({ok:true});','Route-local session cookie explicitly script readable'],
 ['secure','NORMAL',sess('{secure:true,httpOnly:true,sameSite:"lax"}'),readSession+'res.json({ok:true});','Explicit bounded attributes, not full session safety'],
 ['default-httponly','NORMAL',sess('{secure:true,sameSite:"lax"}'),readSession+'res.json({ok:true});','Pinned library defaults HttpOnly true'],
 ['preference','NORMAL','',"res.cookie('theme','dark',{httpOnly:false});res.end('ok');",'UI preference is not established as a session cookie'],
 ['secure-false','UNKNOWN',sess('{secure:false,httpOnly:true}'),readSession+'res.end("ok");','HTTPS/proxy and cookie purpose must not be inferred'],
 ['none-insecure','UNKNOWN',sess('{secure:false,httpOnly:true,sameSite:"none"}'),readSession+'res.end("ok");','Browser rejection and CSRF effects are separate'],
 ['domain','UNKNOWN',sess('{secure:true,httpOnly:true,domain:".example.invalid"}'),readSession+'res.end("ok");','Sharing intent is not known'],
 ['dynamic','UNKNOWN',sess('externalCookie'),readSession+'res.end("ok");','Cookie options supplied externally'],
 ['expiry','UNKNOWN',sess('{secure:true,httpOnly:true,maxAge:3600000}'),readSession+'res.end("ok");','Client expiry is not server invalidation'],
 ['regenerate','NORMAL',sess('{secure:true,httpOnly:true}'),"req.session.regenerate(()=>{req.session.user='owned';res.end('ok');});",'Correct lifecycle intention requires callback execution proof'],
 ['destroy','NORMAL',sess('{secure:true,httpOnly:true}'),"req.session.destroy(()=>res.end('ok'));",'Destroy call is not verified completion'],
]){
 let input=packet(code(setup,body));
 if(id==='route-session')input=packet(input.files[0].content.replace("app.post('/work',", "app.post('/work',session({secret:process.env.SESSION_SECRET,cookie:{secure:true,httpOnly:false}}),"));
 add('COOKIE',id,truth,input,reason);
}
for(const [id,truth,body,reason]of [
 ['unguarded','RISK',"if(!req.session.user)return res.status(403).end();fs.writeFileSync('/owned/state',req.body.value);res.end('ok');",'Closed control assumes authenticated cookie, TLS and no outside CSRF gate'],
 ['client-token','RISK',"if(!req.session.user)return res.status(403).end();const csrfToken=req.body.csrfToken;fs.writeFileSync('/owned/state',req.body.value);res.end('ok');",'Client token is never checked in this closed control'],
 ['prefix-origin','RISK',"if(!req.get('origin').startsWith('https://trusted.invalid'))return;fs.writeFileSync('/owned/state','changed');res.end('ok');",'Prefix is not an exact origin guard'],
 ['origin','NORMAL',"if(req.get('origin')!=='https://trusted.invalid')return res.status(403).end();const s=req.session;fs.writeFileSync('/owned/state','changed');res.end('ok');",'Direct exact origin rejection before mutation; runtime host remains external'],
 ['read-only','NORMAL',readSession+"res.json({ok:true});",'No demonstrated state change'],
 ['token','NORMAL',"if(!verifyToken(req.body.token,req.session))return;fs.writeFileSync('/owned/state','changed');res.end('ok');",'Verifier is stipulated correct in control; analyzer cannot prove it'],
 ['custom','UNKNOWN',"externalAuth(req);externalWrite(req);res.end('ok');",'Unknown authentication and state change'],
 ['same-site','UNKNOWN',readSession+"externalWrite(req);res.end('ok');",'SameSite cannot prove CSRF protection'],
])add('CSRF',id,truth,packet(code(sess('{secure:true,httpOnly:true,sameSite:"none"}'),body)),reason);
