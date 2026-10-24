// Bounded local value provenance. Never establishes authorization or executes a query.
export function writeOrigins({ts,charge,binding,escaped,index,location,fnOf,authResults}) {
 const peel=n=>{while(n&&(ts.isParenthesizedExpression(n)||ts.isAsExpression(n)||ts.isNonNullExpression(n)))n=n.expression;return n;};
 const name=n=>n&&(ts.isIdentifier(n)||ts.isStringLiteral(n))&&/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(n.text)?n.text:null;
 const safety=new WeakMap();
 const unknown=(n,m,reason)=>({source:'UNKNOWN',sourceLocations:n?[location(n,m,'VALUE_ORIGIN_UNRESOLVED')]:[],limitations:[reason]});
 function immutableFunction(fn){
  if(safety.has(fn))return safety.get(fn);
  let safe=true;
  const scan=n=>{charge();if(n!==fn&&ts.isFunctionLike(n))return;if(ts.isDeleteExpression(n)||ts.isPostfixUnaryExpression(n)||ts.isPrefixUnaryExpression(n)&&[ts.SyntaxKind.PlusPlusToken,ts.SyntaxKind.MinusMinusToken].includes(n.operator))safe=false;ts.forEachChild(n,scan);};
  scan(fn);safety.set(fn,safe);return safe;
 }
 function patternPath(pattern,target,prefix=[],depth=0){
  charge();if(!pattern||depth>3)return null;
  if(ts.isIdentifier(pattern))return pattern.text===target?prefix:null;
  if(!ts.isObjectBindingPattern(pattern))return null;
  for(const e of pattern.elements){if(e.dotDotDotToken||e.initializer)return null;const key=name(e.propertyName??e.name);if(!key)return null;const r=patternPath(e.name,target,[...prefix,key],depth+1);if(r)return r;}
  return null;
 }
 return function observe(mod,from,access){
  const fn=fnOf(from),entry=mod.entries.find(e=>e.fn.node===fn&&['NEXT_ROUTE_HANDLER','NEXT_SERVER_FUNCTION'].includes(e.kind));
  if(!entry||!access.authorizationEvidence?.requestEntry||access.clientStatus!=='CLIENT_DECLARATION_LINKED'||!['INSERT','UPDATE','DELETE'].includes(access.operation))return null;
  const limits=['LOCAL_ORIGIN_NOT_RUNTIME_AUTHORIZATION','CLIENT_ROLE_AND_DEPLOYED_POLICY_UNKNOWN','NO_RESOURCE_OWNERSHIP_INFERRED_FROM_FIELD_NAME'];
  const checked=access.authorizationEvidence.authChecks??[];
  const calls=(index(mod)?.nodes??[]).filter(c=>checked.some(a=>{const l=location(c,mod,'');return a.location.line===l.line&&a.location.column===l.column;}));
  const fresh=(source,n)=>({source,sourceLocations:[location(n,mod,'WRITE_VALUE_SOURCE')],limitations:[]});
  const merge=(a,b,n)=>{
   if(a.source==='UNKNOWN'||b.source==='UNKNOWN')return unknown(n,mod,'TRANSFORMATION_OR_BRANCH_UNKNOWN');
   if(a.source===b.source)return {...a,sourceLocations:[...a.sourceLocations,...b.sourceLocations].slice(0,4)};
   if([a.source,b.source].every(s=>['SERVER_CONTROLLED','REQUEST_CONTROLLED'].includes(s)))return {...(a.source==='REQUEST_CONTROLLED'?a:b)};
   return unknown(n,mod,'MIXED_IDENTITY_ORIGIN');
  };
  function origin(original,depth=0,seen=new Set()){
   charge();const n=peel(original);if(!n||depth>8||seen.has(n))return unknown(n,mod,'VALUE_ORIGIN_DEPTH_OR_CYCLE');seen=new Set([...seen,n]);
   if(!immutableFunction(fn))return unknown(n,mod,'LOCAL_MUTATION_UNSUPPORTED');
   for(const call of calls){
    charge();const r=authResults.observe(mod,call,from,n);
    if(r?.valueIsUserId)return {source:r.status==='SESSION_READ_UNVERIFIED'?'SESSION_UNVERIFIED':'VERIFIED_USER_EVIDENCE',sourceLocations:[location(call,mod,'IDENTITY_API_ORIGIN'),...(r.guardLocation?[r.guardLocation]:[])],limitations:['API_AND_ABSENCE_EXIT_NOT_AUTHENTICATION_SUCCESS']};
   }
   if(ts.isStringLiteral(n)||ts.isNumericLiteral(n)||[ts.SyntaxKind.TrueKeyword,ts.SyntaxKind.FalseKeyword,ts.SyntaxKind.NullKeyword].includes(n.kind))return fresh('SERVER_CONTROLLED',n);
   if(ts.isAwaitExpression(n)){
    const call=n.expression;
    if(ts.isCallExpression(call)&&ts.isPropertyAccessExpression(call.expression)&&['json','formData','text'].includes(call.expression.name.text)&&!call.arguments.length){
     const base=peel(call.expression.expression),d=ts.isIdentifier(base)?binding(mod,base.text,base):null;
     if(d===fn.parameters[0]&&entry.kind==='NEXT_ROUTE_HANDLER'&&!index(mod).writes.has(base.text)&&!escaped(mod,d,n))return fresh('REQUEST_CONTROLLED',call);
    }
    return unknown(n,mod,'AWAITED_TRANSFORMATION_UNKNOWN');
   }
   if(ts.isIdentifier(n)){
    if(index(mod).writes.has(n.text))return unknown(n,mod,'ASSIGNED_VALUE_UNKNOWN');
    let d=binding(mod,n.text,n),path=[];
    if(d&&ts.isParameter(d)&&d.parent===fn&&entry.kind==='NEXT_SERVER_FUNCTION'&&!escaped(mod,d,from))return fresh('REQUEST_CONTROLLED',d);
    if(d&&ts.isBindingElement(d)){let v=d;while(v&&!ts.isVariableDeclaration(v))v=v.parent;if(!v)return unknown(n,mod,'DESTRUCTURE_UNKNOWN');path=patternPath(v.name,n.text);if(!path)return unknown(n,mod,'DESTRUCTURE_UNKNOWN');d=v;}
    if(!d||!ts.isVariableDeclaration(d)||fnOf(d)!==fn||!(d.parent.flags&ts.NodeFlags.Const)||d.pos>=n.pos||ts.isIdentifier(d.name)&&escaped(mod,d,from))return unknown(n,mod,'LOCAL_BINDING_UNKNOWN');
    if(path.length){const r=origin(d.initializer,depth+1,seen);return r.source==='REQUEST_CONTROLLED'?r:unknown(n,mod,'OBJECT_FIELD_UNKNOWN');}
    return origin(d.initializer,depth+1,seen);
   }
   if(ts.isPropertyAccessExpression(n)){
    let object=peel(n.expression);
    if(ts.isIdentifier(object)){
     const d=binding(mod,object.text,object);
     if(d&&ts.isVariableDeclaration(d)&&(d.parent.flags&ts.NodeFlags.Const)&&!index(mod).writes.has(object.text)&&!escaped(mod,d,from))object=peel(d.initializer);
    }
    if(object&&ts.isObjectLiteralExpression(object)&&object.properties.length<=16){
     const keys=object.properties.map(p=>(ts.isPropertyAssignment(p)||ts.isShorthandPropertyAssignment(p))?name(p.name):null);
     if(keys.every(Boolean)&&new Set(keys).size===keys.length){const p=object.properties[keys.indexOf(n.name.text)];if(p)return origin(ts.isShorthandPropertyAssignment(p)?p.name:p.initializer,depth+1,seen);}
    }
    const r=origin(n.expression,depth+1,seen);
    return r.source==='REQUEST_CONTROLLED'?r:unknown(n,mod,'PROPERTY_OR_IDENTITY_UNKNOWN');
   }
   if(ts.isPrefixUnaryExpression(n)&&n.operator===ts.SyntaxKind.ExclamationToken){const r=origin(n.operand,depth+1,seen);return ['REQUEST_CONTROLLED','SERVER_CONTROLLED'].includes(r.source)?r:unknown(n,mod,'IDENTITY_TRANSFORMATION_UNKNOWN');}
   if(ts.isBinaryExpression(n)&&[ts.SyntaxKind.QuestionQuestionToken,ts.SyntaxKind.EqualsEqualsEqualsToken,ts.SyntaxKind.ExclamationEqualsEqualsToken].includes(n.operatorToken.kind))return merge(origin(n.left,depth+1,seen),origin(n.right,depth+1,seen),n);
   if(ts.isCallExpression(n)){
    if(ts.isIdentifier(n.expression)&&['String','Number','Boolean'].includes(n.expression.text)&&binding(mod,n.expression.text,n)===undefined&&!mod.imports.has(n.expression.text)&&!index(mod).writes.has(n.expression.text)&&n.arguments.length===1){
     const r=origin(n.arguments[0],depth+1,seen);return ['REQUEST_CONTROLLED','SERVER_CONTROLLED'].includes(r.source)?r:unknown(n,mod,'IDENTITY_OR_UNKNOWN_CONVERSION');
    }
    if(ts.isPropertyAccessExpression(n.expression)){
     const base=peel(n.expression.expression),method=n.expression.name.text;
     if(method==='get'&&n.arguments.length===1&&ts.isStringLiteral(n.arguments[0])){
      let form=false;
      if(ts.isIdentifier(base)){const d=binding(mod,base.text,base);form=ts.isParameter(d??{})&&d.parent===fn&&d.type?.getText(mod.ast)==='FormData'&&binding(mod,'FormData',d)===undefined&&!mod.imports.has('FormData')&&entry.kind==='NEXT_SERVER_FUNCTION';
       if(d&&ts.isVariableDeclaration(d)){const v=peel(d.initializer);form=ts.isAwaitExpression(v??{})&&ts.isCallExpression(v.expression)&&ts.isPropertyAccessExpression(v.expression.expression)&&v.expression.expression.name.text==='formData';}}
      const r=origin(base,depth+1,seen);if(form&&r.source==='REQUEST_CONTROLLED')return r;
     }
     if(method==='trim'&&!n.arguments.length&&ts.isCallExpression(base)&&ts.isIdentifier(base.expression)&&base.expression.text==='String')return origin(base,depth+1,seen);
    }
   }
   return unknown(n,mod,'TRANSFORMATION_OR_SOURCE_NOT_SUPPORTED');
  }
  function fields(original,operator){
   let n=peel(original);
   if(ts.isIdentifier(n??{})){const d=binding(mod,n.text,n);if(d&&ts.isVariableDeclaration(d)&&ts.isIdentifier(d.name)&&(d.parent.flags&ts.NodeFlags.Const)&&!index(mod).writes.has(n.text)&&!escaped(mod,d,from))n=peel(d.initializer);}
   if(!n||!ts.isObjectLiteralExpression(n)||n.properties.length>16){limits.push(n&&ts.isObjectLiteralExpression(n)&&n.properties.length>16?'WRITE_FIELDS_LIMIT':'WRITE_OBJECT_NOT_STATIC');return null;}
   const keys=n.properties.map(p=>(ts.isPropertyAssignment(p)||ts.isShorthandPropertyAssignment(p))?name(p.name):null);
   if(keys.some(k=>!k)||new Set(keys).size!==keys.length){limits.push('WRITE_OBJECT_DYNAMIC_OR_DUPLICATE');return null;}
   return n.properties.map((p,i)=>({name:keys[i],operator,location:location(p,mod,'WRITE_ARGUMENT_FIELD'),...origin(ts.isShorthandPropertyAssignment(p)?p.name:p.initializer)}));
  }
  let chain=from,mutation,filters=[],filterStatus='STATIC_FILTERS';
  while(ts.isPropertyAccessExpression(chain.parent)&&chain.parent.expression===chain&&ts.isCallExpression(chain.parent.parent)){
   charge();chain=chain.parent.parent;const method=chain.expression.name.text;
   if(['insert','update','delete'].includes(method)){if(mutation)return null;mutation=chain;}
   else if(method==='eq'&&chain.arguments.length===2&&name(chain.arguments[0])&&ts.isStringLiteral(chain.arguments[0]))filters.push({name:chain.arguments[0].text,operator:'eq',location:location(chain,mod,'WRITE_ROW_FILTER'),...origin(chain.arguments[1])});
   else if(method==='match'&&chain.arguments.length===1){const f=fields(chain.arguments[0],'match');if(f)filters.push(...f);else filterStatus='UNKNOWN';}
   else if(!['select','single','maybeSingle'].includes(method)){filterStatus='UNKNOWN';limits.push('FILTER_OR_CHAIN_NOT_SUPPORTED');}
   if(filters.length>8){filters=[];filterStatus='UNKNOWN';limits.push('WRITE_FILTER_LIMIT');break;}
  }
  if(!mutation)return null;
  const data=access.operation==='DELETE'?[]:mutation.arguments.length>=1?fields(mutation.arguments[0],'field'):null;
  return {status:'LOCAL_VALUE_ORIGIN_EVIDENCE',operationLocation:location(mutation,mod,'WRITE_OPERATION'),dataStatus:access.operation==='DELETE'?'NO_PAYLOAD':data?'STATIC_FIELDS':'UNKNOWN',dataFields:data??[],filterStatus,filters,limitations:[...new Set(limits)]};
 };
}
