// Static middleware contracts only; never invoke target callbacks or a rate-limit store.
export function rateLimiting(api){
 const {ts,input,result,tick,note,object,native,loc,append}=api;
 const scalar=v=>v?.tag==='constant'&&!v.unknown&&Object.hasOwn(v,'constant');
 const plain=v=>v?.tag==='object'&&v.ref?.plainData&&!v.unknown&&!v.ref.unknown;
 const get=(v,k)=>v?.ref?.properties.get(k);
 const clean=v=>v&&!v.unknown&&!v.ref?.unknown;
 const optionNames=['limit','max','windowMs','keyGenerator','skip','handler','store','passOnStoreError','skipFailedRequests','skipSuccessfulRequests','standardHeaders','legacyHeaders','message','statusCode'];
 const baseLimits=['DECLARED_VERSION_NOT_INSTALLED_VERSION','EXTERNAL_GATEWAY_WAF_AND_DEPLOYMENT_UNKNOWN','RATE_BUDGET_BUSINESS_REQUIREMENTS_UNKNOWN',
  'AUTHENTICATION_AND_DISTRIBUTED_ABUSE_NOT_PROVEN','PROXY_HOPS_HEADER_REPLACEMENT_AND_IP_NORMALIZATION_UNKNOWN'];
 const integer=(v,fallback)=>!v?fallback:scalar(v)&&Number.isSafeInteger(v.constant)?v.constant:undefined;
 function fingerprint(opts){return JSON.stringify([!!opts?.unknown,!!opts?.ref?.unknown,...optionNames.map(k=>{
  const v=get(opts,k);return !v?null:scalar(v)?['constant',v.constant]:[v.tag,!!v.unknown,!!v.ref?.unknown,v.target?.node?.pos];
 })]);}
 function body(v,state){
  if(!clean(v)||!v.target||v.target.node.asteriskToken||v.target.node.modifiers?.some(m=>m.kind===ts.SyntaxKind.AsyncKeyword))return;
  tick(state.mod);const fn=v.target.node;
  if(fn.parameters.some(p=>!ts.isIdentifier(p.name)||p.initializer||p.dotDotDotToken))return;
  if(!ts.isBlock(fn.body))return {fn,expression:fn.body,returns:true};
  if(fn.body.statements.length!==1)return;
  const st=fn.body.statements[0];
  return {fn,expression:ts.isReturnStatement(st)||ts.isExpressionStatement(st)?st.expression:undefined,returns:ts.isReturnStatement(st)};
 }
 function keyOf(v,state){
  if(!v)return 'IP_DECLARED_PROXY_UNKNOWN';
  const b=body(v,state);if(!b?.expression||!b.returns)return 'KEY_UNKNOWN';
  if(ts.isStringLiteral(b.expression))return 'GLOBAL_CONSTANT_KEY';
  const e=b.expression,p=b.fn.parameters[0]?.name.text;
  if(ts.isPropertyAccessExpression(e)&&ts.isIdentifier(e.expression)&&e.expression.text===p&&e.name.text==='ip')return 'IP_DECLARED_PROXY_UNKNOWN';
  if(ts.isCallExpression(e)&&ts.isPropertyAccessExpression(e.expression)&&ts.isIdentifier(e.expression.expression)
   &&e.expression.expression.text===p&&e.expression.name.text==='get'&&e.arguments.length===1&&ts.isStringLiteral(e.arguments[0]))return 'REQUEST_HEADER_KEY_UNVERIFIED';
  return 'KEY_UNKNOWN';
 }
 function callback(v,state,kind){
  if(!v)return kind==='skip'?'NO_SKIP':'DEFAULT_STOP';
  const b=body(v,state);if(!b?.expression)return 'UNKNOWN';
  if(kind==='skip')return !b.returns?'UNKNOWN':b.expression.kind===ts.SyntaxKind.TrueKeyword?'ALWAYS_SKIP':b.expression.kind===ts.SyntaxKind.FalseKeyword?'NO_SKIP':'UNKNOWN';
  const e=b.expression,p=b.fn.parameters[2]?.name.text;
  return p&&ts.isCallExpression(e)&&ts.isIdentifier(e.expression)&&e.expression.text===p&&e.arguments.length===0?'NEXT_ON_EXCEEDED':'UNKNOWN';
 }
 function dependency(mod,spec){
  if(spec==='express-rate-limit')return native('express-rate-limit',mod);
  if(spec==='@upstash/ratelimit')note(mod,'UPSTASH_RATE_LIMIT_EXECUTION_CONTRACT_NOT_SUPPORTED');
 }
 function property(base,key){
  if(clean(base)&&base.native==='express-rate-limit'&&['rateLimit','default'].includes(key))return native('express-rate-limit',base.nativeMod,base.ref);
 }
 function factory(callable,node,args,state){
  if(callable?.native!=='express-rate-limit')return;
  const manifest=(input.nodeManifests??[]).filter(m=>state.mod.filePath.startsWith(m.filePath==='package.json'?'':m.filePath.slice(0,-12))).sort((a,b)=>b.filePath.length-a.filePath.length)[0];
  const opts=args[0],version=manifest?.['express-rate-limit'];
  const limit=integer(get(opts,'limit'),integer(get(opts,'max'),5)),window=integer(get(opts,'windowMs'),60000);
  const skip=callback(get(opts,'skip'),state,'skip'),handler=callback(get(opts,'handler'),state,'handler'),key=keyOf(get(opts,'keyGenerator'),state);
  const bool=k=>!get(opts,k)||scalar(get(opts,k))&&typeof get(opts,k).constant==='boolean';
  const extraValid=bool('passOnStoreError')&&bool('skipFailedRequests')&&bool('skipSuccessfulRequests')
   &&(!get(opts,'statusCode')||Number.isInteger(integer(get(opts,'statusCode')))&&integer(get(opts,'statusCode'))>=100&&integer(get(opts,'statusCode'))<=599)
   &&(!get(opts,'message')||scalar(get(opts,'message'))&&typeof get(opts,'message').constant==='string')
   &&(!get(opts,'legacyHeaders')||scalar(get(opts,'legacyHeaders'))&&typeof get(opts,'legacyHeaders').constant==='boolean')
   &&(!get(opts,'standardHeaders')||scalar(get(opts,'standardHeaders'))&&[true,false,'draft-6','draft-7','draft-8'].includes(get(opts,'standardHeaders').constant));
  const known=clean(callable)&&ts.isCallExpression(node)&&args.length<=1&&version==='7.5.0'&&(!opts||plain(opts)&&[...opts.ref.properties.keys()].every(k=>optionNames.includes(k)))
   &&Number.isSafeInteger(limit)&&limit>=0&&window>0&&window<=2147483647&&!get(opts,'store')&&extraValid&&!state.uncertain;
  const limiter=object('rate-middleware');
  limiter.rate={opts,known,skip,handler,key,limit,window,signature:fingerprint(opts),location:loc(node,state.mod,'RATE_LIMIT_FACTORY'+(ts.isSourceFile(state.fn.node)?'_MODULE':''),state.fn)};
  observe('RATE_LIMIT_DECLARATION',limiter.rate.location,[limiter.rate.location],[...baseLimits,...(!known?['RATE_LIMIT_VERSION_OPTIONS_OR_STORE_UNKNOWN']:[])],state);
  if(!known)note(state.mod,'RATE_LIMIT_VERSION_OPTIONS_OR_STORE_UNKNOWN');
  return {value:limiter};
 }
 const stack=receiver=>receiver.rateStack??(receiver.rateStack=[]);
 function use(receiver,args,node,state){
  const entries=stack(receiver);if(entries.length>=50){receiver.rateUnknown=true;note(state.mod,'RATE_LIMIT_SCOPE_LIMIT');return;}
  const mount=args.length===1?'/':scalar(args[0])?args[0].constant:undefined,mid=args.at(-1);
  if(mid?.tag==='express-router'){mid.rateParentUnknown=true;return;}
  if(mid?.tag==='rate-middleware'&&args.length<=2&&typeof mount==='string'&&/^\/[\w/-]*$/.test(mount))entries.push({middleware:mid,mount,location:loc(node,state.mod,'RATE_LIMIT_MOUNT',state.fn)});
  else receiver.rateUnknown=true;
 }
 function route(receiver,args,node,state){
  const path=scalar(args[0])?args[0].constant:undefined,policies=[...stack(receiver)];let uncertain=!!receiver.rateUnknown||!!state.uncertain;
  for(const mid of args.slice(1,-1)){
   tick(state.mod);if(policies.length>=50){uncertain=true;note(state.mod,'RATE_LIMIT_SCOPE_LIMIT');break;}
   if(mid?.tag==='rate-middleware')policies.push({middleware:mid,mount:'/',location:loc(node,state.mod,'RATE_LIMIT_ROUTE_MOUNT',state.fn)});else uncertain=true;
  }
  if(typeof path!=='string'||!/^\/[\w/-]*$/.test(path))uncertain=true;
  return {policies:policies.filter(p=>typeof path==='string'&&(p.mount==='/'||path===p.mount||path.startsWith(p.mount+'/'))),uncertain,owner:receiver,registration:loc(node,state.mod,'RATE_LIMIT_REQUEST_REGISTRATION',state.fn)};
 }
 function entry(scope,isolate){
  if(!scope)return;
  return {policies:scope.policies.map(p=>({...p,middleware:isolate(p.middleware),rate:{...p.middleware.rate,opts:isolate(p.middleware.rate.opts)}})),
   uncertain:scope.uncertain||!!scope.owner.rateParentUnknown,registration:scope.registration,
   any:scope.policies.length>0||stack(scope.owner).length>0||!!scope.owner.rateParentUnknown};
 }
 function observe(kind,location,trace,limitations,state,ruleId='JS_RATE_LIMIT_CONTEXT'){
  append(result.nodeUses,{ruleId,kind,operation:'EXPRESS_RATE_LIMIT',location,trace:trace.slice(0,20),limitations:limitations.slice(0,30)},state.mod);
 }
 function response(node,state){
  const scope=state.context.rateSecurity;if(!scope?.any)return;
  const response=loc(node,state.mod,'RATE_LIMIT_RESPONSE',state.fn);
  if(scope.uncertain||state.uncertain){observe('RATE_LIMIT_APPLICATION_UNKNOWN',response,[scope.registration],baseLimits,state);return;}
  if(!scope.policies.length){observe('RATE_LIMIT_NOT_APPLICABLE',response,[scope.registration],baseLimits,state);return;}
  const intact=scope.policies.every(p=>clean(p.middleware)&&p.rate.known&&fingerprint(p.rate.opts)===p.rate.signature);
  if(!intact||scope.policies.length!==1){observe('RATE_LIMIT_APPLICATION_UNKNOWN',response,[scope.registration],baseLimits,state);return;}
  const p=scope.policies[0],r=p.rate;
  const limits=[...baseLimits,r.key,'MEMORY_STORE_PROCESS_LOCAL_DECLARATION','STORE_CONNECTIVITY_AND_MULTI_INSTANCE_EFFECT_UNKNOWN',
   ...(get(r.opts,'passOnStoreError')?.constant===true?['STORE_ERROR_FAIL_OPEN_DECLARED']:['STORE_ERROR_NOT_PASSED_BY_DEFAULT']),
   'LIMIT_COUNT_'+r.limit,'WINDOW_MS_'+r.window];
  const skip=r.skip,handler=r.handler;
  const bypass=skip==='ALWAYS_SKIP'||handler==='NEXT_ON_EXCEEDED';
  const unknown=skip==='UNKNOWN'||handler==='UNKNOWN'||['KEY_UNKNOWN','REQUEST_HEADER_KEY_UNVERIFIED'].includes(r.key)
   ||get(r.opts,'skipFailedRequests')?.constant===true||get(r.opts,'skipSuccessfulRequests')?.constant===true;
  const kind=unknown?'RATE_LIMIT_BLOCKING_UNKNOWN':bypass?'RATE_LIMIT_EXPLICIT_BYPASS':r.limit===0?'RATE_LIMIT_ZERO_BLOCKS_BOUND':'RATE_LIMIT_DEFAULT_STOP_BOUND';
  const trace=[r.location,p.location,scope.registration,response];
  observe(kind,response,trace,limits,state);
  if(!bypass||unknown)return;
  // Only pre-existing supported work observations corroborate a candidate; route names never do.
  const same=(a,b)=>a.filePath===b.filePath&&a.line===b.line&&a.column===b.column&&a.kind===b.kind;
  const work=state.context.resources.filter(s=>s.kind==='HTTP_REQUEST_CALL'
   ?result.httpUses.some(u=>same(u.location,s)&&u.kind==='STATIC_DESTINATION')
   :/^NODE_FILE_(?:WRITE|DELETE|RENAME)/.test(s.kind)&&result.resourceUses.some(u=>same(u.location,s)&&u.executionObserved&&u.kind!=='UNRESOLVED_RESOURCE'));
  for(const sink of work.slice(0,8)){
   tick(state.mod);const flow=[r.location,p.location,scope.registration,sink];
   const limitations=[...limits,skip==='ALWAYS_SKIP'?'SKIP_ALWAYS_TRUE':'EXCEEDED_HANDLER_CALLS_NEXT','OPERATION_COST_AND_SENSITIVITY_NOT_PROVEN'];
   observe('RATE_LIMIT_BYPASS_TO_WORK',sink,flow,limitations,state,'JS_RATE_LIMIT_BYPASS_REVIEW');
   append(result.findings,{ruleId:'JS_RATE_LIMIT_BYPASS_REVIEW',kind:'CWE-799',confidence:'HIGH',disposition:'REVIEW_REQUIRED',
    source:r.location,sink,flow,defenses:[],limitations,
    message:'요청 제한을 건너뛰는 설정이 서버 작업 경로에 연결됩니다.',
    recommendation:'표시한 라이브러리 7.5.0의 skip 또는 초과 handler와 등록 순서를 확인하세요. 제한 초과 시 작업 전에 응답을 종료하고 정상 요청은 유지하세요. 계정·IP·전역 예산을 구분하고 사용자 A/B, 초과·복구·저장소 장애를 소량의 로컬 요청으로 검증하세요. 외부 WAF와 업무 허용량은 별도로 확인하세요.'},state.mod);
  }
 }
 return {dependency,property,factory,use,route,entry,response};
}
