// Symbolic Promise values and bounded await states. No microtask/event executor.
export function asyncBoundaries(api){
 const {ts,modules,tick,note,unknown,constant,loc,append,result,fork}=api;
 const primitive=v=>v&&!v.ref&&!v.unknown&&(v.tag==='constant'||['numeric','boolean','allowlistedIdentifier'].includes(v.tag));
 let intrinsicTrusted;
 const promise=(settlement,payload=unknown())=>({tag:'async-promise',trace:[],
  ref:{properties:new Map(),unknown:false,trace:[],nodeIdentity:{}},asyncResult:{settlement,payload}});
 function evidence(kind,node,state,trace=[]){append(result.nodeUses,{ruleId:'JS_SERVER_ENTRY_CONTEXT',kind,operation:'BOUNDED_ASYNC_FLOW',
  location:loc(node,state.mod,kind,state.fn),trace,limitations:['STATIC_ASYNC_MODEL_NOT_RUNTIME_COMPLETION_PROOF',
   ...(state.uncertain?['CONDITIONAL_ASYNC_PATH']:[]),
   ...(state.context.asyncPostAwait?['POST_AWAIT_HEAP_AND_INTERLEAVING_UNVERIFIED']:[]),
   ...(kind==='COMPLETION_CONFIRMED_BY_SUPPORTED_MODEL'?['AWAIT_OPERAND_SETTLEMENT_ONLY_NOT_FUNCTION_OR_IO_COMPLETION']:[])]},state.mod);}
 function begin(state){
  state.asyncFrame={summary:{awaited:false,unknown:false,rejected:false},post:false};
  evidence('ASYNC_CALL_CONNECTED',state.fn.node,state);evidence('PRE_AWAIT_REACHABLE',state.fn.node,state);
 }
 function intrinsic(callee,args,state){
  if(!state.nodeMode||!ts.isPropertyAccessExpression(callee)||!ts.isIdentifier(callee.expression)||callee.expression.text!=='Promise'
    ||!['resolve','reject'].includes(callee.name.text))return;
  if(state.vars.has('Promise')||state.mod.declared.has('Promise')||state.mod.imports.has('Promise'))return;
  if(intrinsicTrusted===undefined){
   intrinsicTrusted=true;
   for(const m of modules.values()){
    tick(state.mod);const i=m.syntaxIndex;
    if(!i||['Promise','global','globalThis'].some(n=>i.writes.has(n)||i.exportWrites.has(n)||i.aliases.has(n)||(i.argumentUses.get(n)?.length??0)>0))intrinsicTrusted=false;
   }
  }
  if(!intrinsicTrusted){note(state.mod,'PROMISE_INTRINSIC_ORIGIN_UNKNOWN');return promise('UNKNOWN');}
  if(args.length>1)return promise('UNKNOWN');
  const v=args[0]??constant(undefined);
  return promise(callee.name.text==='reject'?'REJECTED':primitive(v)?'FULFILLED':'UNKNOWN',v);
 }
 function awaitValue(v,node,state){
  const frame=state.asyncFrame;
  if(!frame)return v;
  evidence('AWAIT_OPERAND_EVALUATED',node,state);evidence('AWAIT_SUSPENDED',node,state);
  frame.summary.awaited=true;
  const settlement=!v.unknown&&!v.ref?.unknown&&v.tag==='async-promise'&&v.asyncResult?v.asyncResult.settlement:primitive(v)?'FULFILLED':'UNKNOWN';
  if(settlement==='REJECTED'){
   frame.summary.rejected=true;state.asyncStop=true;state.asyncRejected=true;
   evidence('REJECTION_PATH_POSSIBLE',node,state);return unknown();
  }
  if(settlement!=='FULFILLED'){
   frame.summary.unknown=true;state.asyncStop=true;
   note(state.mod,'UNSUPPORTED_ASYNC_BOUNDARY');evidence('FULFILLMENT_PATH_POSSIBLE',node,state);
   evidence('REJECTION_PATH_POSSIBLE',node,state);evidence('UNSUPPORTED_ASYNC_BOUNDARY',node,state);return unknown();
  }
  if(!frame.post){
   frame.preMutations=new Set(state.nodeMutations);
   const detached=fork(state);state.vars=detached.vars;state.thisValue=detached.thisValue;state.forkRefs=detached.forkRefs;
   state.nodeMutations=new Set();
   state.context=Object.assign(Object.create(state.context),{asyncPostAwait:true,unresolved:true});
   frame.post=true;
  }
  state.uncertain=true;state.exposureUncertain=true;
  evidence('FULFILLMENT_PATH_POSSIBLE',node,state);evidence('POST_AWAIT_CONDITIONAL',node,state);
  evidence('COMPLETION_CONFIRMED_BY_SUPPORTED_MODEL',node,state);
  return v.asyncResult?.payload??v;
 }
 function finish(r,state){
  const summary=state.asyncFrame.summary;
  if((r.asyncRejected||r.constructorAbrupt)&&!r.values.length&&!summary.unknown){evidence('REJECTION_PATH_POSSIBLE',state.fn.node,state);return promise('REJECTED');}
  const returns=[...r.values,...(!r.stops?[constant(undefined)]:[])];
  if(!summary.awaited&&!summary.rejected&&!state.uncertain&&returns.length===1){
   if(primitive(returns[0]))return promise('FULFILLED',returns[0]);
   if(returns[0].tag==='async-promise'&&!returns[0].unknown&&!returns[0].ref?.unknown&&returns[0].asyncResult)
    return promise(returns[0].asyncResult.settlement,returns[0].asyncResult.payload);
  }
  return promise('UNKNOWN');
 }
 return {begin,intrinsic,awaitValue,finish,evidence};
}
