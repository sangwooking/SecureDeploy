import path from 'node:path';

// A bounded library contract over symbolic values. No model code or queries run.
export function mongooseContracts(api) {
  const {ts,input,tick,note,loc,object,native,unknown,constant,append,result,union}=api;
  const rule='JS_MONGOOSE_SELECTOR_INPUT_FLOW', instances=new Map();
  const literal=v=>v?.tag==='constant'&&!v.unknown;
  const valid=v=>{
    const seen=new Set();
    for(let ref=v?.ref;ref;ref=ref.originParent){if(ref.unknown||seen.has(ref))return false;seen.add(ref);}
    return !!v?.ref&&!v.unknown;
  };
  function dependency(mod) {
    const manifest=(input.nodeManifests??[]).filter(m=>mod.filePath.startsWith(path.posix.dirname(m.filePath)==='.'?'':path.posix.dirname(m.filePath)+'/'))
      .sort((a,b)=>b.filePath.length-a.filePath.length)[0];
    const version=/^(?:\^|~)?([4-8])\.\d+\.\d+$/.exec(manifest?.mongoose??'');
    const key=manifest?.filePath??'';
    if(!instances.has(key)){
      const v=native('mongoose',mod);v.ref.mongooseMajor=version?Number(version[1]):0;
      v.ref.properties.set('@sanitize',constant(false));instances.set(key,v);
    }
    return instances.get(key);
  }
  function property(base,key) {
    if(base.native==='mongoose'&&key==='default')return base;
    if(base.native==='mongoose'&&key==='Schema')return {...native('mongoose-schema',base.nativeMod),ref:base.ref};
  }
  function scan(v,state,depth=0,seen=new Set()) {
    tick(state.mod);
    if(!v||depth>3||seen.has(v))return {trace:[],uncertain:true,trusted:false};
    seen.add(v);
    if(v.selectorString||!v.unknown&&(['STRING','STRING_MAP'].includes(v.inputShape)||v.tag==='numeric'||v.tag==='boolean')||literal(v)&&!v.ref)
      return {trace:[],uncertain:!!v.traceTruncated,trusted:!!v.selectorTrusted};
    const own={trace:v.trace??[],uncertain:!!v.unknown||!!v.ref?.unknown,trusted:!!v.selectorTrusted||!!v.ref?.selectorTrusted};
    if(v.ref?.properties){
      const children=[];
      for(const [key,child]of v.ref.properties){
        if(children.length>=40)return {...own,uncertain:true};
        const c=scan(child,state,depth+1,seen);if(typeof key!=='string'||key.startsWith('$')||key.includes('.')||key==='__proto__')c.uncertain=true;
        children.push(c);
      }
      own.trace=union({trace:own.trace},...children.map(c=>({trace:c.trace}))).trace;
      own.uncertain||=children.some(c=>c.uncertain);own.trusted||=children.some(c=>c.trusted);
    }
    return own;
  }
  function options(v) {
    if(!v)return {known:true};
    if(v.tag!=='object'||v.unknown||v.ref?.unknown||!v.ref)return {known:false};
    if([...v.ref.properties.keys()].some(k=>!['sanitizeFilter','strictQuery'].includes(k)))return {known:false};
    const setting=v.ref.properties.get('sanitizeFilter');
    return {known:!setting||literal(setting)&&typeof setting.constant==='boolean',setting};
  }
  function trackFilter(v,state,versions=[],seen=new Set(),depth=0) {
    if(!v?.ref||seen.has(v.ref)||depth>3)return versions;
    tick(state.mod);seen.add(v.ref);v.ref.mongooseTracked=true;
    versions.push({ref:v.ref,revision:v.ref.mongooseRevision??0});
    for(const child of [...v.ref.properties.values()].slice(0,40))trackFilter(child,state,versions,seen,depth+1);
    return versions;
  }
  const callback=v=>v?.tag==='function'&&!!v.target&&!v.unknown&&!v.ref?.unknown;
  const projection=v=>!v||literal(v)&&(v.constant===null||typeof v.constant==='string');
  function executionUnknown(query,node,state,reason) {
    note(state.mod,reason);
    if(state.context.setup)return;
    append(result.nodeUses,{ruleId:rule,kind:reason==='MONGOOSE_CALLBACK_VERSION_UNSUPPORTED'?'CALLBACK_VERSION_UNSUPPORTED':'UNKNOWN',
      operation:query.ref.operation,location:query.ref.createdAt,
      trace:[...scan(query.ref.properties.get('@filter'),state).trace,loc(node,state.mod,'MONGOOSE_UNVERIFIED_EXECUTION_REQUEST',state.fn)].slice(0,20),
      limitations:[reason,'NO_SUPPORTED_QUERY_EXECUTION_PROOF']},state.mod);
  }
  function callbackExecution(query,node,state,fn) {
    const version=query.ref.properties.get('@model')?.ref?.mongooseMajor??0;
    if(!version||version>=7){
      query.ref.properties.set('@executionInvalid',constant(true));
      executionUnknown(query,node,state,version>=7?'MONGOOSE_CALLBACK_VERSION_UNSUPPORTED':'MONGOOSE_CALLBACK_VERSION_UNKNOWN');
      return false;
    }
    consume(query,node,state,fn);
    note(state.mod,'MONGOOSE_CALLBACK_BODY_NOT_ANALYZED');
    // Do not execute the callback or retain subsequent Mongoose protection
    // certainty. Unrelated SQL/environment paths keep their existing contract.
    const body=fn.target.node.body;
    if(!body||!ts.isBlock(body)||body.statements.length){
      query.ref.properties.get('@model')?.ref?.originParent?.properties.set('@callbackEffectsUnknown',constant(true));
      note(state.mod,'MONGOOSE_CALLBACK_EFFECTS_UNKNOWN');
    }
    return true;
  }
  function consume(query,node,state,fn) {
    if(query?.tag!=='mongoose-query'||state.context.setup)return;
    const ref=query.ref,model=ref.properties.get('@model'),filter=ref.properties.get('@filter');
    if(ref.properties.has('@executionInvalid')){executionUnknown(query,node,state,'MONGOOSE_EXECUTION_CONTRACT_UNKNOWN');return;}
    if(ref.executionRequested){executionUnknown(query,node,state,'MONGOOSE_REPEAT_OR_MIXED_EXECUTION_UNKNOWN');return;}
    ref.executionRequested=true;
    const proof=scan(filter,state),option=ref.properties.get('@sanitize')??model?.ref?.originParent?.properties.get('@sanitize');
    const version=model?.ref?.mongooseMajor??0,hasOption=literal(option)&&option.constant===true;
    const filterObject=filter?.tag==='object'&&filter.ref&&!filter.unknown&&!filter.ref.unknown;
    const rootProtected=filterObject&&[...filter.ref.properties.keys()].every(k=>typeof k==='string'&&!k.startsWith('$')&&!k.includes('.'));
    const configUnknown=!literal(option)||typeof option.constant!=='boolean'||hasOption&&version<6
      ||!!model?.ref?.originParent?.properties.get('@trustedUnknown')||!!ref.properties.get('@optionsUnknown')
      ||!!model?.ref?.originParent?.properties.get('@callbackEffectsUnknown');
    const schema=model?.ref?.properties.get('@schema');
    const filterChanged=(ref.filterVersions??[]).some(v=>v.ref.unknown||(v.ref.mongooseRevision??0)!==v.revision);
    const unresolved=!valid(query)||!valid(model)||schema&&!valid(schema)||!version||state.uncertain||proof.uncertain||configUnknown||filterChanged;
    const status=unresolved?'UNKNOWN':!proof.trace.length?'STATIC_OR_STRING_FILTER'
      :hasOption&&!proof.trusted&&rootProtected?'SANITIZE_FILTER_DECLARED'
      :hasOption&&!proof.trusted&&!rootProtected?'UNKNOWN':'SELECTOR_INPUT_CANDIDATE';
    const location=ref.createdAt,execution=loc(node,state.mod,fn?'MONGOOSE_CALLBACK_EXECUTION_REQUEST':'MONGOOSE_QUERY_EXECUTION_REQUEST',state.fn);
    const trace=[...proof.trace,...(model?.ref?.origin??[]),
      ...(fn?[loc(fn.target.node,fn.target.mod,'MONGOOSE_CALLBACK_REFERENCE',fn.target)]:[]),execution].slice(0,20);
    const limitations=['STATIC_SELECTOR_NOT_RUNTIME_EXPLOIT_PROOF','DECLARED_VERSION_NOT_INSTALLED_VERSION',
      'SCHEMA_CAST_HOOKS_MIDDLEWARE_AND_DATABASE_NOT_VERIFIED',
      ...(fn?['MONGOOSE_CALLBACK_BODY_NOT_ANALYZED']:[]),
      ...(status==='UNKNOWN'?['MONGOOSE_SELECTOR_CONTRACT_UNKNOWN']:[]),
      ...(!valid(model)||schema&&!valid(schema)?['MONGOOSE_MODEL_ORIGIN_UNRESOLVED']:[]),
      ...(state.uncertain?['MONGOOSE_REQUEST_PATH_UNRESOLVED']:[]),
      ...(proof.uncertain?['MONGOOSE_FILTER_FLOW_UNRESOLVED']:[]),
      ...(configUnknown?['MONGOOSE_PROTECTION_UNRESOLVED']:[]),
      ...(filterChanged?['MONGOOSE_FILTER_MUTATION_UNKNOWN']:[]),
      ...(!version?['MONGOOSE_DECLARED_VERSION_UNKNOWN']:[]),
      ...(proof.trusted?['MONGOOSE_TRUSTED_EXCEPTION']:[]),
      ...(hasOption&&version<6?['SANITIZE_FILTER_VERSION_UNSUPPORTED']:[]),
      ...(hasOption&&!rootProtected?['ROOT_FILTER_SANITIZATION_NOT_PROVEN']:[])];
    append(result.nodeUses,{ruleId:rule,kind:status,operation:ref.operation,location,trace,limitations},state.mod);
    if(status==='UNKNOWN')note(state.mod,'MONGOOSE_SELECTOR_CONTRACT_UNKNOWN');
    if(status!=='SELECTOR_INPUT_CANDIDATE'||trace.length>=20)return;
    append(result.findings,{ruleId:rule,kind:'CWE-943',confidence:'HIGH',disposition:'REVIEW_REQUIRED',
      source:proof.trace[0],sink:location,flow:trace,defenses:[],limitations,
      message:'사용자가 보낸 객체 형태의 값이 데이터 조회 조건에 전달될 가능성이 있습니다.',
      recommendation:'요청 필드의 타입을 검증하고 필요한 값만 명시적인 문자열 등으로 제한하세요. 선언 버전에서 지원되는 sanitizeFilter와 trusted 예외를 확인하고, 로컬에서 객체형 입력·정상 문자열 입력을 비교한 뒤 재검사하세요. 실제 DB 접근과 공격 성공은 별도 검증이 필요합니다.'},state.mod);
  }
  function call(node,callee,receiver,args,state,global,callable) {
    const method=ts.isPropertyAccessExpression(callee)?callee.name.text:undefined;
    if(callable?.native==='mongoose-schema'&&ts.isNewExpression(node)){
      const schema=object('mongoose-schema');
      const definition=node.arguments?.[0];
      const flatScalars=definition&&ts.isObjectLiteralExpression(definition)&&definition.properties.every(p=>{
        tick(state.mod);
        return ts.isPropertyAssignment(p)&&!ts.isComputedPropertyName(p.name)&&ts.isIdentifier(p.initializer)
          &&['String','Number','Boolean','Date'].includes(p.initializer.text)
          &&!state.vars.has(p.initializer.text)&&!state.mod.declared.has(p.initializer.text);
      });
      if(!valid(callable)||args.length!==1||args[0]?.tag!=='object'||args[0]?.ref?.unknown||!flatScalars)schema.ref.unknown=true;
      return {value:schema};
    }
    if(receiver?.native==='mongoose'){
      if(!valid(receiver))return {value:unknown()};
      if(method==='set'){
        const ref=state.forkRefs?.get(receiver.ref)??receiver.ref;
        if(args.length===2&&literal(args[0])&&args[0].constant==='sanitizeFilter')ref.properties.set('@sanitize',args[1]);
        else if(!(args.length===2&&literal(args[0])&&args[0].constant==='strictQuery'))ref.unknown=true;
        return {value:receiver};
      }
      if(method==='trusted'&&args.length===1){
        if(receiver.ref.mongooseMajor<6){note(state.mod,'SANITIZE_FILTER_VERSION_UNSUPPORTED');return {value:{...args[0],unknown:true}};}
        if(args[0].ref)args[0].ref.selectorTrusted=true;
        else receiver.ref.properties.set('@trustedUnknown',constant(true));
        return {value:{...args[0],selectorTrusted:true}};
      }
      if(method==='model'){
        const key=literal(args[0])&&typeof args[0].constant==='string'?'@model:'+args[0].constant:undefined;
        const prior=key&&receiver.ref.properties.get(key);
        if(args.length===1&&prior)return {value:prior};
        if(!key||args.length<2||args.length>3||args[1]?.tag!=='mongoose-schema'||!valid(args[1])){
          note(state.mod,'MONGOOSE_MODEL_REGISTRATION_UNKNOWN');return {value:unknown()};
        }
        if(prior){receiver.ref.unknown=true;note(state.mod,'MONGOOSE_MODEL_REGISTRATION_UNKNOWN');return {value:unknown()};}
        if([...receiver.ref.properties.keys()].filter(k=>k.startsWith('@model:')).length>=100){
          note(state.mod,'MONGOOSE_MODEL_LIMIT');return {value:unknown()};
        }
        const model=object('mongoose-model');model.ref.originParent=receiver.ref;model.ref.mongooseMajor=receiver.ref.mongooseMajor;
        model.ref.origin=[loc(node,state.mod,'MONGOOSE_MODEL_DECLARATION',state.fn)];model.ref.properties.set('@schema',args[1]);
        receiver.ref.properties.set(key,model);return {value:model};
      }
    }
    if(receiver?.tag==='mongoose-model'&&['find','findOne'].includes(method)){
      const query=object('mongoose-query');query.ref.originParent=receiver.ref;
      query.ref.properties.set('@model',receiver);query.ref.properties.set('@filter',args[0]??constant(null));
      query.ref.filterVersions=trackFilter(args[0],state);
      query.ref.operation=method;query.ref.createdAt=loc(node,state.mod,'MONGOOSE_QUERY_FILTER',state.fn);
      const fn=args.length>=2&&callback(args.at(-1))?args.at(-1):undefined;
      const ordinary=fn?args.slice(0,-1):args;
      const opt=options(ordinary[2]);if(opt.setting)query.ref.properties.set('@sanitize',opt.setting);
      const argumentsKnown=ordinary.length>=1&&ordinary.length<=3&&projection(ordinary[1])&&opt.known;
      if(!argumentsKnown)query.ref.properties.set('@optionsUnknown',constant(true));
      if(!state.context.setup)append(result.nodeUses,{ruleId:rule,kind:'QUERY_CREATED_EXECUTION_NOT_OBSERVED',operation:method,
        location:query.ref.createdAt,trace:scan(args[0],state).trace,limitations:['AWAIT_EXEC_OR_SUPPORTED_CALLBACK_REQUIRED','MODEL_SCHEMA_RUNTIME_NOT_VERIFIED']},state.mod);
      if(fn&&argumentsKnown){
        if(!callbackExecution(query,node,state,fn))return {value:unknown()};
      }else if(!argumentsKnown){
        query.ref.properties.set('@executionInvalid',constant(true));executionUnknown(query,node,state,'MONGOOSE_CALLBACK_OR_ARGUMENT_UNKNOWN');
      }
      return {value:query};
    }
    if(receiver?.tag==='mongoose-query'){
      if(method==='setOptions'&&args.length===1){const opt=options(args[0]);if(opt.setting)receiver.ref.properties.set('@sanitize',opt.setting);
        if(!opt.known)receiver.ref.properties.set('@optionsUnknown',constant(true));return {value:receiver};}
      if(method==='exec'&&args.length===0){consume(receiver,node,state);return {value:unknown()};}
      if(method==='exec'){
        if(args.length===1&&callback(args[0]))callbackExecution(receiver,node,state,args[0]);
        else {receiver.ref.properties.set('@executionInvalid',constant(true));executionUnknown(receiver,node,state,'MONGOOSE_CALLBACK_OR_ARGUMENT_UNKNOWN');}
        return {value:unknown()};
      }
      receiver.ref.unknown=true;note(state.mod,'MONGOOSE_QUERY_CHAIN_UNKNOWN');return {value:unknown()};
    }
    if(['find','findOne'].includes(method)&&receiver?.unknown&&!state.context.setup){
      const proof=scan(args[0],state);
      if(!proof.trace.length)return;
      append(result.nodeUses,{ruleId:rule,kind:'UNKNOWN',operation:method,location:loc(node,state.mod,'UNVERIFIED_QUERY_CALL',state.fn),
        trace:proof.trace,limitations:['MODEL_ORIGIN_UNVERIFIED_NOT_A_MONGOOSE_SINK_PROOF']},state.mod);
    }
  }
  return {dependency,property,call,consume};
}
