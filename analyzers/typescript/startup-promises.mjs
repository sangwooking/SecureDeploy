// Static native Promise continuation, never a microtask executor or thenable runtime.
export function startupPromises(api){
 const{ts,modules,tick,note,loc,append,result,unknown,invoke,native}=api;
 const mutationKnown=state=>{
  const queue=[state.mod.filePath,state.context.entry?.filePath].filter(Boolean),seen=new Set();
  for(let i=0;i<queue.length;i++){const m=modules.get(queue[i]);if(!m||seen.has(m.filePath))continue;seen.add(m.filePath);tick(m);
   if(!m.syntaxIndex||m.syntaxIndex.promiseMutation)return true;
   for(const edge of m.syntaxIndex?.dependencies??[]){tick(m);if(!edge.spec.startsWith('.'))continue;const target=api.findModule(m,edge.spec,edge.mode??'require');if(target&&!seen.has(target.filePath))queue.push(target.filePath);}
  }return false;
 };
 function property(base,key,state){if(state.context.setup&&base.tag==='async-promise'&&!base.unknown&&!base.ref?.unknown&&key==='then')return native('startup-promise-then',state.mod);}
 function call(node,receiver,args,state){
  if(!state.context.setup||state.context.classConstructorFlow||receiver?.tag!=='async-promise'||!ts.isPropertyAccessExpression(node.expression)||node.expression.name.text!=='then')return;
  if(receiver.unknown||receiver.ref?.unknown||!(receiver.nativePromiseOrigin||receiver.nativeAsyncOrigin)||mutationKnown(state)){
   note(state.mod,receiver.unknown||receiver.ref?.unknown?'STARTUP_PROMISE_VALUE_UNKNOWN':!(receiver.nativePromiseOrigin||receiver.nativeAsyncOrigin)?'STARTUP_PROMISE_ORIGIN_UNKNOWN':'STARTUP_PROMISE_MUTATION_UNKNOWN');return{value:unknown()};
  }
  if(receiver.asyncResult?.settlement==='REJECTED'){note(state.mod,'STARTUP_REJECTED_PROMISE_NO_SUCCESS_ROUTE');return{value:unknown()};}
  const cb=args[0];if(args.length<1||args.length>2||!cb?.target||cb.unknown||cb.ref?.unknown||cb.target.node.asteriskToken){note(state.mod,'STARTUP_SUCCESS_CALLBACK_UNRESOLVED');return{value:unknown()};}
  const at=loc(node,state.mod,'STARTUP_PROMISE_FULFILLMENT_POSSIBLE',state.fn),target=loc(cb.target.node,cb.target.mod,'STARTUP_SUCCESS_CALLBACK',cb.target);
  const context=Object.assign(Object.create(state.context),{bootstrapTrace:[...(state.context.bootstrapTrace??[]),...(receiver.nativeAsyncOrigin?[receiver.nativeAsyncOrigin]:[]),at,target].slice(-12),bootstrapConditional:true,checks:[...(state.context.checks??[])],defenses:[],resources:[]});
  append(result.nodeUses,{ruleId:'JS_SERVER_ENTRY_CONTEXT',kind:'STARTUP_PROMISE_FULFILLMENT_POSSIBLE',operation:'NATIVE_PROMISE_THEN_SUCCESS_ONLY',location:at,trace:context.bootstrapTrace,
   limitations:['CONDITIONAL_REGISTRATION_NOT_RUNTIME_SUCCESS','REJECTION_PENDING_AND_RUNTIME_GLOBALS_UNVERIFIED','NOT_USER_DEFINED_THENABLE']},state.mod);
  invoke(cb.target,[receiver.asyncResult?.settlement==='FULFILLED'?receiver.asyncResult.payload:unknown()],state.depth+1,context,state.stack,true,true);
  return{value:unknown()};
 }
 return{property,call};
}
