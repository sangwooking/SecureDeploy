import path from 'node:path';

// Immutable request-field identities and bounded branch-local facts, not a heap
// executor. Format checks never certify primitive type or unrelated fields.
export function fieldValidation(api) {
  const {ts,input,tick,note,value,loc,native,result,append}=api;
  const libraries=new Map();
  const same=(a,b)=>a?.root===b?.root&&a?.epoch===b?.epoch&&JSON.stringify(a?.parts)===JSON.stringify(b?.parts);
  const eligible=v=>v?.fieldOrigin&&!v.unknown&&v.fieldOrigin.parts.length===2
    &&['body','query'].includes(v.fieldOrigin.parts[0]);
  function dependency(mod){
    const m=(input.nodeManifests??[]).filter(m=>mod.filePath.startsWith(path.posix.dirname(m.filePath)==='.'?'':path.posix.dirname(m.filePath)+'/'))
      .sort((a,b)=>b.filePath.length-a.filePath.length)[0];
    const key=m?.filePath??'';
    if(!libraries.has(key)){
      const v=native('validator',mod);v.ref.validator13=/^(?:\^|~)?13\.\d+\.\d+$/.test(m?.validator??'');libraries.set(key,v);
    }
    return libraries.get(key);
  }
  function root(base,key,node,state){
    if(base.unknown)return;
    base.fieldRoot??={};
    return {root:base.fieldRoot,parts:[key],epoch:state.fieldEpoch??0,source:loc(node,state.mod,'HTTP_FIELD_SOURCE',state.fn)};
  }
  function read(base,key,node,state){
    if(!base.fieldOrigin||base.ref)return;
    if(base.fieldOrigin.parts.length>=2||key.length>80||['__proto__','prototype','constructor'].includes(key))return;
    return apply({...base,fieldOrigin:{...base.fieldOrigin,parts:[...base.fieldOrigin.parts,key],
      epoch:state.fieldEpoch??0,source:loc(node,state.mod,'HTTP_FIELD_SOURCE',state.fn)}},state);
  }
  function apply(v,state){
    if(!eligible(v))return v;
    const facts=(state.fieldFacts??[]).filter(f=>same(f.origin,v.fieldOrigin));
    const type=facts.find(f=>f.mode==='TYPEOF_STRING'&&f.accepted);
    const email=facts.find(f=>f.mode==='EMAIL');
    return {...v,fieldString:!!type,fieldEmail:email,
      fieldDefenses:facts.flatMap(f=>[f.check,f.origin.source]).slice(0,8),
      fieldValidationUncertain:!!v.fieldValidationUncertain||!!state.fieldGuardUsed&&!!state.fieldUnsafe&&!type};
  }
  function call(node,receiver,args,state){
    if(receiver?.native!=='validator'||!ts.isPropertyAccessExpression(node.expression)||node.expression.name.text!=='isEmail')return;
    if(receiver.unknown||receiver.ref?.unknown||!receiver.ref?.validator13||args.length!==1||!eligible(args[0])||state.depth!==0){
      note(state.mod,'FIELD_VALIDATOR_CONTRACT_UNKNOWN');return;
    }
    const source=args[0];
    return {value:value('boolean',[],{fieldPredicate:{origin:source.fieldOrigin,mode:'EMAIL',invert:false,
      check:loc(node,state.mod,'FIELD_EMAIL_FORMAT_CHECK',state.fn),epoch:state.fieldEpoch??0},
      predicateInput:{trace:source.trace,unknown:true}})};
  }
  function typeName(v,state){
    if(!eligible(v)||state.depth!==0)return value('type-name');
    return value('type-name',[],{fieldTypeOrigin:v.fieldOrigin});
  }
  function compare(node,left,right,state){
    if(![ts.SyntaxKind.EqualsEqualsEqualsToken,ts.SyntaxKind.ExclamationEqualsEqualsToken].includes(node.operatorToken.kind))return;
    const typed=left.fieldTypeOrigin?left:right,other=typed===left?right:left;
    if(!typed.fieldTypeOrigin||other.unknown||other.tag!=='constant'||other.constant!=='string')return;
    return value('boolean',[],{fieldPredicate:{origin:typed.fieldTypeOrigin,mode:'TYPEOF_STRING',
      invert:node.operatorToken.kind===ts.SyntaxKind.ExclamationEqualsEqualsToken,
      check:loc(node,state.mod,'FIELD_STRING_TYPE_CHECK',state.fn),epoch:state.fieldEpoch??0}});
  }
  function refine(node,condition,yes,no){
    if(condition.fieldValidationUncertain){
      for(const state of [yes,no]){state.fieldGuardUsed=true;state.fieldUnsafe=true;}
      return false;
    }
    let n=node;
    for(let depth=0;depth<8;depth++){
      if(ts.isParenthesizedExpression(n))n=n.expression;
      else if(ts.isPrefixUnaryExpression(n)&&n.operator===ts.SyntaxKind.ExclamationToken)n=n.operand;
      else break;
    }
    const p=condition.fieldPredicate;
    if(!p||condition.unknown||yes.depth!==0||yes.fieldUnsafe||p.epoch!==(yes.fieldEpoch??0)
      ||!(ts.isIdentifier(n)||ts.isCallExpression(n)||p.mode==='TYPEOF_STRING'&&ts.isBinaryExpression(n)))return false;
    for(const [state,truth]of [[yes,true],[no,false]]){
      tick(state.mod);
      const accepted=truth!==!!p.invert;
      const fact={...p,accepted,check:{...p.check,kind:p.mode==='EMAIL'
        ?accepted?'FIELD_EMAIL_ACCEPTED_BRANCH':'FIELD_EMAIL_REJECTED_BRANCH':'FIELD_STRING_TYPE_BRANCH'}};
      // A false typeof branch does not certify a string.
      const facts=(state.fieldFacts??[]).filter(f=>!(same(f.origin,p.origin)&&f.mode===p.mode));
      if(p.mode==='EMAIL'||accepted)facts.push(fact);
      if(facts.length>32){state.fieldUnsafe=true;note(state.mod,'FIELD_VALIDATION_FACT_LIMIT');continue;}
      state.fieldFacts=facts;state.fieldGuardUsed=true;
    }
    append(result.nodeUses,{ruleId:'JS_MONGOOSE_SELECTOR_INPUT_FLOW',kind:'FIELD_VALIDATION_OBSERVED',
      operation:p.mode+'_BOOLEAN_CONDITION',location:p.check,trace:[p.origin.source],
      limitations:['FIELD_SCOPED_ONLY','BRANCH_FACT_NOT_RUNTIME_VALIDATION_SUCCESS','DECLARED_VALIDATOR_NOT_INSTALLED_VERSION',
        ...(p.mode==='EMAIL'?['EMAIL_FORMAT_NOT_PRIMITIVE_STRING_OR_FULL_QUERY_DEFENSE']:[])]},yes.mod);
    return true;
  }
  function invalidate(state){
    if(!state.nodeMode||state.context.setup)return;
    state.fieldFacts=[];state.fieldEpoch=(state.fieldEpoch??0)+1;state.fieldUnsafe=true;
  }
  function escape(state){
    if(!state.fieldGuardUsed)return;
    invalidate(state);Object.defineProperty(state.context,'fieldScopeEscape',{value:true,writable:true,configurable:true});
    note(state.mod,'FIELD_VALIDATION_CROSS_FUNCTION_UNKNOWN');
  }
  function merge(state,branches){
    const first=branches[0];if(!first)return;
    state.fieldFacts=(first.fieldFacts??[]).filter(f=>branches.every(b=>(b.fieldFacts??[]).some(g=>same(f.origin,g.origin)
      &&f.mode===g.mode&&f.accepted===g.accepted&&f.check.filePath===g.check.filePath&&f.check.line===g.check.line&&f.check.column===g.check.column)));
    state.fieldUnsafe=!!state.fieldUnsafe||branches.some(b=>b.fieldUnsafe);
    state.fieldEpoch=Math.max(state.fieldEpoch??0,...branches.map(b=>b.fieldEpoch??0));
    state.fieldGuardUsed=!!state.fieldGuardUsed||branches.some(b=>b.fieldGuardUsed);
  }
  return {dependency,root,read,apply,call,typeName,compare,refine,invalidate,merge,escape};
}
