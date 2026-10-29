// Evaluation-only discovery. Never invokes an uncalled factory or invents a mount.
export function staticRoutes(api){
 const {ts,tick,note,loc,limits,functionValue,writtenNames,unknown,controls,audit}=api;
 const registrations=new Map(),seenFactories=new WeakSet(),rowsByLocation=new Map();
 let flows=0;
 const verbs=new Set(['get','post','put','patch','delete','head','options','all']);
 const key=l=>`${l.filePath}:${l.line}:${l.column}`;
 const pathOf=n=>n&&(ts.isStringLiteral(n)||ts.isNoSubstitutionTemplateLiteral(n))?n.text:undefined;
 const disjoint=(a,b)=>typeof a==='string'&&typeof b==='string'&&/^\/[A-Za-z0-9_/-]*$/.test(a)&&/^\/[A-Za-z0-9_/-]*$/.test(b)
  &&a.replace(/\/+$/,'').toLowerCase()!==b.replace(/\/+$/,'').toLowerCase();
 function row(category,location,handler,reason){
  const id=key(location),prior=rowsByLocation.get(id);if(prior)return prior;
  if(audit.rows.length>=Math.min(100,limits.maxResults)){note(handler?.mod??audit.anchor,'STATIC_ROUTE_ROW_LIMIT');audit.limitations.add('STATIC_ROUTE_ROW_LIMIT');return;}
  const r={id,category,registration:location,handler:handler?loc(handler.node,handler.mod,'STATIC_HANDLER_DEFINITION',handler):undefined,
   bootstrap:'UNVERIFIED',mount:category==='A'?'STATIC_SETUP_LINKED':'UNVERIFIED',runtimeExposure:'UNKNOWN',
   traceStatus:reason??'NOT_INSPECTED',limitations:['EVALUATION_ONLY_NOT_FINAL_FINDING','STATIC_CODE_NOT_RUNTIME_EXPOSURE_PROOF']};
  audit.rows.push(r);rowsByLocation.set(id,r);return r;
 }
 function registration(node,receiver,args,state,method){
  if(!verbs.has(method)||args.length<2)return;
  const at=loc(node,state.mod,'STATIC_ROUTE_REGISTRATION',state.fn);audit.anchor??=state.mod;
  registrations.set(key(at),{node,method,path:args[0]?.tag==='constant'?args[0].constant:undefined});
  if(receiver.unknown||receiver.ref?.unknown)row('E',at,undefined,'RECEIVER_STATE_UNKNOWN');
  else if(args[0]?.tag!=='constant'||args[0].unknown||typeof args[0].constant!=='string')row('E',at,undefined,'DYNAMIC_ROUTE_PATH_UNKNOWN');
  else if(!args.at(-1)?.target||args.at(-1).unknown||args.at(-1).ref?.unknown)row('D',at,undefined,'HANDLER_UNCONNECTED');
 }
 function enqueue(r,handler,control,mod,extra={}){
  if(!r)return;
  if(!handler?.target||handler.unknown||handler.ref?.unknown){r.traceStatus='HANDLER_UNCONNECTED';return;}
  const fn=handler.target;
  if(!fn.node.body||fn.node.asteriskToken||fn.node.parameters.length<1||fn.node.parameters.length>3
    ||fn.node.parameters.some(p=>!ts.isIdentifier(p.name)||p.initializer||p.dotDotDotToken)){
   r.traceStatus='HANDLER_PARAMETER_CONTRACT_UNKNOWN';return;
  }
  if(control.opaque){r.traceStatus='MIDDLEWARE_CONTEXT_UNKNOWN';return;}
  for(const p of control.priors??[]){
   tick(mod);if(!disjoint(control.path,p.path)&&(controls.proof([...p.prefix,p.handler])||!controls.passive([...p.prefix,p.handler]))){
    r.traceStatus='PRIOR_ROUTE_OR_MIDDLEWARE_UNKNOWN';return;
   }
  }
  if(control.prefix.length){
   if(controls.proof(control.prefix)){r.traceStatus='LOCAL_MIDDLEWARE_TERMINATES';return;}
   if(!controls.passive(control.prefix)){r.traceStatus='MIDDLEWARE_CONTEXT_UNKNOWN';return;}
  }
  if(flows>=Math.min(20,limits.maxFunctions,limits.maxResults)){r.traceStatus='STATIC_ROUTE_FLOW_LIMIT';audit.limitations.add(r.traceStatus);return;}
  flows++;r.traceStatus='QUEUED_CONDITIONAL';
  mod.entries.push({fn,kind:'EXPRESS_HANDLER',registration:r.registration,uncertain:true,staticCandidate:r,...extra});
 }
 function scanFactory(fn){
  if(seenFactories.has(fn.node)||!fn.node.body||!ts.isBlock(fn.node.body)||fn.node.asteriskToken)return;
  seenFactories.add(fn.node);const mod=fn.mod;tick(mod);
  const vars=new Map(fn.closure??[]),localRouterHints=new Set(),shadow=name=>{
   if(ts.isIdentifier(name))vars.set(name.text,unknown());
   else for(const e of name.elements??[])if(e.name)shadow(e.name);
  };
  fn.node.parameters.forEach(p=>shadow(p.name));
  const locals=n=>{tick(mod);if(ts.isFunctionLike(n)){if(n.name)shadow(n.name);return;}
   if(ts.isClassDeclaration(n)){if(n.name)shadow(n.name);return;}
   if(ts.isVariableDeclaration(n)){
    const init=n.initializer;
    if(ts.isIdentifier(n.name)&&init&&ts.isCallExpression(init)&&ts.isPropertyAccessExpression(init.expression)
      &&init.expression.name.text==='Router'&&ts.isIdentifier(init.expression.expression)&&vars.get(init.expression.expression.text)?.native==='express')localRouterHints.add(n.name.text);
    shadow(n.name);
   }ts.forEachChild(n,locals);};locals(fn.node.body);
  const writes=new Set(writtenNames(fn.node,{mod})),invalidRefs=new Set(),factoryPriors=new Map(),opaqueRefs=new Set();
  for(const name of writes){const v=vars.get(name);if(v?.tag==='express-router')invalidRefs.add(v.ref.nodeIdentity);}
  const escapes=n=>{tick(mod);if(ts.isFunctionLike(n))return;
   if(ts.isCallExpression(n))for(const arg of n.arguments)if(ts.isIdentifier(arg)){
    const v=vars.get(arg.text);if(v?.tag==='express-router')invalidRefs.add(v.ref.nodeIdentity);
   }
   ts.forEachChild(n,escapes);
  };escapes(fn.node.body);
  const state={mod,fn,vars,nodeMode:true,depth:0,stack:new Set(),uncertain:true,context:{setup:true,unresolved:true,checks:[],defenses:[],resources:[]}};
  const member=n=>ts.isPropertyAccessExpression(n)&&ts.isIdentifier(n.expression)&&verbs.has(n.name.text);
  const resolveHandler=n=>ts.isArrowFunction(n)||ts.isFunctionExpression(n)?functionValue(n,state,'staticHandler')
   :ts.isIdentifier(n)?vars.get(n.text):undefined;
  const scan=n=>{
   tick(mod);if(ts.isFunctionLike(n))return;
   if(ts.isCallExpression(n)&&ts.isPropertyAccessExpression(n.expression)&&n.expression.name.text==='use'&&ts.isIdentifier(n.expression.expression)){
    const receiver=vars.get(n.expression.expression.text);if(receiver?.tag==='express-router')opaqueRefs.add(receiver.ref.nodeIdentity);
   }
   if(ts.isCallExpression(n)&&member(n.expression)&&n.arguments.length>=2){
    const name=n.expression.expression.text,receiver=vars.get(name),original=fn.closure?.get(name);
    if(receiver?.tag==='express-router'||original?.tag==='express-router'||localRouterHints.has(name)){
     const at=loc(n,mod,'STATIC_ROUTE_REGISTRATION',fn);
     if(!rowsByLocation.has(key(at))){
      const handler=resolveHandler(n.arguments.at(-1));
      const receiverKnown=receiver?.tag==='express-router'&&!receiver.unknown&&!receiver.ref?.unknown&&!invalidRefs.has(receiver.ref.nodeIdentity);
      const handlerKnown=handler?.target&&!handler.unknown&&!handler.ref?.unknown;
      const r=row(!receiverKnown?'E':!handlerKnown?'D':'C',at,handler?.target,'FACTORY_NOT_INVOKED');
      if(r){
       r.registrationScope='UNCALLED_FACTORY';
       r.limitations.push('FACTORY_NOT_INVOKED','FACTORY_LOCAL_STATE_NOT_EXECUTED','FACTORY_PRECONDITIONS_UNVERIFIED');
       const direct=ts.isExpressionStatement(n.parent)&&n.parent.parent===fn.node.body;
       if(!receiverKnown)r.traceStatus=localRouterHints.has(name)?'FACTORY_LOCAL_RECEIVER_NOT_CREATED':'FACTORY_RECEIVER_STATE_UNKNOWN';
       else if(!direct)r.traceStatus='FACTORY_BRANCH_OR_NESTING_UNKNOWN';
       else if(!ts.isStringLiteral(n.arguments[0])&&!ts.isNoSubstitutionTemplateLiteral(n.arguments[0]))r.traceStatus='DYNAMIC_ROUTE_PATH_UNKNOWN';
       else{
        const prefix=n.arguments.slice(1,-1).map(resolveHandler);
        if(prefix.some(v=>!v?.target||v.unknown))r.traceStatus='MIDDLEWARE_CONTEXT_UNKNOWN';
        else enqueue(r,handler,{prefix,opaque:!!receiver.controlOpaque||opaqueRefs.has(receiver.ref.nodeIdentity),path:pathOf(n.arguments[0]),priors:factoryPriors.get(receiver.ref.nodeIdentity)},mod);
        const priors=factoryPriors.get(receiver.ref.nodeIdentity)??[];
        priors.push({path:pathOf(n.arguments[0]),prefix,handler});factoryPriors.set(receiver.ref.nodeIdentity,priors);
       }
      }
     }
    }
   }
   ts.forEachChild(n,scan);
  };scan(fn.node.body);
 }
 function finish(routes,reachable,routeControls,loaded){
  const connected=new Set([...reachable].flatMap(a=>a.routes));
  for(const route of routes){
   const mod=route.target.mod;tick(mod);audit.anchor??=mod;
   const at=route.location,category=connected.has(route)?'A':'B';
   const prior=rowsByLocation.get(key(at));
   if(prior){
    if(['A','B'].includes(prior.category)){prior.category='E';prior.traceStatus='MULTIPLE_REGISTRATION_INSTANCES_UNVERIFIED';}
    continue;
   }
   const r=row(category,at,route.target,category==='A'?'USE_PRODUCTION_ANALYSIS':'MOUNT_UNVERIFIED');
   if(r&&category==='B'){
    const control=routeControls.get(route),priors=control.owner.routes.slice(0,control.before).map(p=>{
     const c=routeControls.get(p);return {path:registrations.get(key(p.location))?.path,prefix:c.prefix,handler:c.handler};
    });
    enqueue(r,control.handler,{...control,path:registrations.get(key(at))?.path,priors},mod,{web:route.web,rate:route.rate});
   }
  }
  const seen=new Set();
  const exported=(v,depth)=>{
   if(!v||seen.has(v)||depth>2)return;seen.add(v);
   if(v.target&&!v.unknown&&!v.ref?.unknown)scanFactory(v.target);
   if(v.ref&&!v.ref.unknown)for(const child of v.ref.properties.values()){tick(audit.anchor);exported(child,depth+1);}
  };
  for(const [mod,v]of loaded){audit.anchor??=mod;tick(mod);exported(v,0);}
 }
 return {registration,finish};
}
