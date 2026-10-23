import path from 'node:path';

// A small library contract and a closed initialization grammar, not a target runtime.
export function sequelizeContracts(api) {
  const {ts,input,modules,tick,note,loc,object,native,unknown}=api;
  const rule='JS_SEQUELIZE_SQL_INPUT_FLOW';
  const un=n=>{while(n&&ts.isParenthesizedExpression(n))n=n.expression;return n;};
  const id=(n,name)=>n&&ts.isIdentifier(n)&&n.text===name;
  const member=(n,name)=>n&&ts.isPropertyAccessExpression(n)&&n.name.text===name;
  const declaration=mod=>(input.nodeManifests??[]).filter(m=>mod.filePath.startsWith(path.posix.dirname(m.filePath)==='.'?'':path.posix.dirname(m.filePath)+'/'))
    .sort((a,b)=>b.filePath.length-a.filePath.length)[0]?.sequelize;
  function version(mod){return /^(?:\^|~)?([4-6])\.\d+\.\d+$/.exec(declaration(mod)??'')?.[1];}
  function create(mod,node){
    if(!version(mod)){note(mod,'SEQUELIZE_DECLARED_API_VERSION_UNKNOWN');return unknown();}
    const instance=object('sequelize-instance');instance.ref.origin=[loc(node,mod,'SEQUELIZE_DECLARED_INSTANCE_ORIGIN')];
    instance.ref.sequelizeMajor=Number(version(mod));return instance;
  }
  function call(node,receiver,args,state,callable){
    if(callable?.native==='sequelize'&&ts.isNewExpression(node)&&!callable.unknown&&!callable.ref?.unknown){
      if(args.some(v=>v.ref&&(v.tag!=='object'||v.unknown||v.ref.unknown||v.ref.properties.has('hooks')||v.ref.properties.has('dialectModule')))){
        note(state.mod,'SEQUELIZE_CONSTRUCTOR_EFFECTS_UNKNOWN');return {value:unknown()};
      }
      return {value:create(callable.nativeMod,node)};
    }
    if(receiver?.tag!=='sequelize-instance'||receiver.unknown||receiver.ref?.unknown||!member(node.expression,'query'))return;
    if(args.length<1||args.length>2){note(state.mod,'SEQUELIZE_QUERY_ARGUMENT_CONTRACT_UNKNOWN');return {value:unknown()};}
    const options=args[1],knownOptions=!options||options.tag==='object'&&!options.unknown&&!options.ref?.unknown
      &&![...options.ref.properties.keys()].some(k=>!['model','mapToModel','type','plain','raw','nest','bind','replacements','logging'].includes(k));
    const sql=args[0],trace=[...sql.trace,...(receiver.ref.origin??[])];
    api.observe({...sql,trace:sql.trace.length?trace.slice(0,20):[],unknown:sql.unknown||!knownOptions||trace.length>20},node,state,rule,'CWE-89','SEQUELIZE_RAW_QUERY');
    return {value:unknown()};
  }

  // Match grammar nodes structurally; placeholders bind identifiers, not source text.
  const patterns=new Map();
  function match(node,source,bindings,mod){
    if(!patterns.has(source))patterns.set(source,ts.createSourceFile('grammar.js',source,ts.ScriptTarget.Latest,true).statements[0]);
    const visit=(a,b)=>{
      a=un(a);b=un(b);tick(mod);if(!a||!b)return a===b;
      if(ts.isIdentifier(b)&&b.text.startsWith('$')){
        if(!ts.isIdentifier(a))return false;
        if(bindings.has(b.text))return bindings.get(b.text)===a.text;
        if(['process','require','module','Object','console','__dirname'].includes(a.text)||[...bindings.values()].includes(a.text))return false;
        bindings.set(b.text,a.text);return true;
      }
      if(a.kind!==b.kind)return false;
      if(ts.isIdentifier(a)||ts.isStringLiteral(a)||ts.isNumericLiteral(a))return a.text===b.text;
      if(ts.isVariableDeclarationList(a)){
        if(a.declarations.length!==b.declarations.length)return false;
        return a.declarations.every((d,i)=>visit(d,b.declarations[i]));
      }
      const ac=[],bc=[];ts.forEachChild(a,c=>{ac.push(c)});ts.forEachChild(b,c=>{bc.push(c)});
      return ac.length===bc.length&&ac.every((c,i)=>visit(c,bc[i]));
    };
    return visit(node,patterns.get(source));
  }
  function pure(node,allowed,mod){
    const n=un(node);if(!n)return true;tick(mod);
    if(ts.isStringLiteral(n)||ts.isNumericLiteral(n)||[ts.SyntaxKind.TrueKeyword,ts.SyntaxKind.FalseKeyword,ts.SyntaxKind.NullKeyword].includes(n.kind))return true;
    if(ts.isIdentifier(n))return allowed.has(n.text);
    if(ts.isPropertyAccessExpression(n))return !n.questionDotToken&&pure(n.expression,allowed,mod)&&!['__proto__','prototype','constructor'].includes(n.name.text);
    if(ts.isObjectLiteralExpression(n))return n.properties.every(p=>ts.isPropertyAssignment(p)&&!ts.isComputedPropertyName(p.name)
      &&!['__proto__','prototype','constructor','hooks'].includes(p.name.text)&&pure(p.initializer,allowed,mod));
    if(ts.isArrayLiteralExpression(n))return n.elements.every(e=>pure(e,allowed,mod));
    if(ts.isBinaryExpression(n)&&n.operatorToken.kind===ts.SyntaxKind.BarBarToken)return pure(n.left,allowed,mod)&&pure(n.right,allowed,mod);
    return false;
  }
  function configuration(mod){
    if(!mod)return false;
    return mod.ast.statements.every(s=>ts.isExpressionStatement(s)&&(ts.isStringLiteral(s.expression)
      ||ts.isBinaryExpression(s.expression)&&s.expression.operatorToken.kind===ts.SyntaxKind.EqualsToken
      &&member(s.expression.left,'exports')&&id(s.expression.left.expression,'module')
      &&ts.isObjectLiteralExpression(s.expression.right)&&pure(s.expression.right,new Set(['process']),mod)));
  }
  function model(mod){
    let fn;
    for(const s of mod.ast.statements){tick(mod);
      if(ts.isExpressionStatement(s)&&ts.isStringLiteral(s.expression))continue;
      if(fn||!ts.isExpressionStatement(s)||!ts.isBinaryExpression(s.expression)||s.expression.operatorToken.kind!==ts.SyntaxKind.EqualsToken
        ||!member(s.expression.left,'exports')||!id(s.expression.left.expression,'module'))return;
      fn=s.expression.right;
    }
    if(!fn||!ts.isFunctionExpression(fn)||fn.asteriskToken||fn.modifiers?.length||fn.parameters.length!==2
      ||fn.parameters.some(p=>!ts.isIdentifier(p.name)||p.initializer||p.dotDotDotToken))return;
    const [client,types]=fn.parameters.map(p=>p.name.text);let name,binding,returned=false;
    const define=n=>{
      if(!ts.isCallExpression(n)||!member(n.expression,'define')||!id(n.expression.expression,client)||n.arguments.length<2||n.arguments.length>3
        ||!ts.isStringLiteral(n.arguments[0])||!n.arguments.slice(1).every(v=>pure(v,new Set([types]),mod)))return false;
      name=n.arguments[0].text;return !!name&&!['__proto__','constructor','prototype','sequelize','Sequelize'].includes(name);
    };
    for(const s of fn.body.statements){tick(mod);if(returned)return;
      if(ts.isVariableStatement(s)&&s.declarationList.declarations.length===1&&!binding){const d=s.declarationList.declarations[0];if(!ts.isIdentifier(d.name)||!d.initializer||!define(d.initializer))return;binding=d.name.text;}
      else if(ts.isReturnStatement(s)&&s.expression&&(binding?id(s.expression,binding):define(s.expression)))returned=true;
      else return;
    }
    return returned?name:undefined;
  }
  function summarize(mod){
    const hasLibrary=mod.ast.statements.some(s=>{tick(mod);return ts.isVariableStatement(s)&&s.declarationList.declarations.some(d=>d.initializer&&ts.isCallExpression(d.initializer)&&id(d.initializer.expression,'require')&&d.initializer.arguments[0]?.text==='sequelize');});
    if(!hasLibrary)return;
    const bindings=new Map(),allowed=new Set(['process']),variables=new Set();
    let instanceName,dbName,constructorName,constructed=false,registry=false,associated=false,exported=false,instanceExport=false,constructorExport=false;
    const evidence=[];const set=(role,name)=>{if(bindings.has(role)&&bindings.get(role)!==name)return false;bindings.set(role,name);return true;};
    const construction=(name,n)=>{
      if(!n||!ts.isNewExpression(n)||!id(n.expression,constructorName)||!n.arguments?.length||!n.arguments.every(a=>pure(a,allowed,mod)))return false;
      if(instanceName&&name!==instanceName)return false;instanceName=name;set('$connection',name);evidence.push(loc(n,mod,'SEQUELIZE_DECLARED_INSTANCE_ORIGIN'));return true;
    };
    for(const s of mod.ast.statements){tick(mod);if(exported)return;
      if(ts.isExpressionStatement(s)&&ts.isStringLiteral(s.expression))continue;
      if(ts.isVariableStatement(s)){
        for(const d of s.declarationList.declarations){
          if(!ts.isIdentifier(d.name)||!d.initializer||variables.has(d.name.text)||['process','require','module','Object','console','__dirname'].includes(d.name.text))return;variables.add(d.name.text);
          const name=d.name.text,n=d.initializer;
          if(ts.isCallExpression(n)&&id(n.expression,'require')&&n.arguments.length===1&&ts.isStringLiteral(n.arguments[0])){
            const spec=n.arguments[0].text;
            if(spec==='sequelize'){if(constructorName)return;constructorName=name;set('$Engine',name);}
            else if(spec==='fs'||spec==='node:fs'){if(!set('$fs',name))return;}
            else if(spec==='path'||spec==='node:path'){if(!set('$path',name))return;}
            else if(spec.startsWith('.')&&configuration(api.findModule(mod,spec)))allowed.add(name);
            else return;
          }else if(ts.isObjectLiteralExpression(n)&&n.properties.length===0){if(dbName)return;dbName=name;set('$db',name);}
          else if(ts.isNewExpression(n)){if(constructed||!construction(name,n))return;constructed=true;}
          else if(pure(n,allowed,mod))allowed.add(name);else return;
        }
        continue;
      }
      if(ts.isIfStatement(s)&&!constructed&&pure(s.expression,allowed,mod)&&s.elseStatement){
        const branch=n=>{
          const statements=ts.isBlock(n)?n.statements:[n];if(statements.length!==1||!ts.isVariableStatement(statements[0]))return false;
          const ds=statements[0].declarationList;if(ds.flags&ts.NodeFlags.BlockScoped||ds.declarations.length!==1)return false;
          const d=ds.declarations[0];return ts.isIdentifier(d.name)&&!variables.has(d.name.text)&&!['process','require','module','Object','console','__dirname'].includes(d.name.text)&&construction(d.name.text,d.initializer);
        };
        if(!branch(s.thenStatement)||!branch(s.elseStatement))return;constructed=true;variables.add(instanceName);continue;
      }
      if(!constructed)return;
      if(match(s,`$fs.readdirSync(__dirname).filter(function($file){return ($file.indexOf('.') !== 0) && ($file !== 'index.js');}).forEach(function($file){var $model=$connection.import($path.join(__dirname,$file));$db[$model.name]=$model;});`,new Map(bindings),mod)){
        if(registry||instanceExport||!dbName||path.posix.basename(mod.filePath)!=='index.js'||!bindings.has('$fs')||!bindings.has('$path'))return;
        registry=true;evidence.push(loc(s,mod,'SEQUELIZE_STATIC_MODEL_INVENTORY'));continue;
      }
      if(match(s,`Object.keys($db).forEach(function($key){if('associate' in $db[$key]){$db[$key].associate($db);}});`,new Map(bindings),mod)){
        if(!registry||associated)return;associated=true;continue;
      }
      if(ts.isExpressionStatement(s)&&ts.isCallExpression(s.expression)){
        let call=s.expression;
        while(ts.isCallExpression(call)&&ts.isPropertyAccessExpression(call.expression)&&['then','catch'].includes(call.expression.name.text)){
          if(!call.arguments.length||!call.arguments.every(fn=>(ts.isFunctionExpression(fn)||ts.isArrowFunction(fn))&&ts.isBlock(fn.body)
            &&fn.parameters.every(p=>ts.isIdentifier(p.name)&&!p.initializer&&!p.dotDotDotToken)
            &&fn.body.statements.every(st=>ts.isExpressionStatement(st)&&ts.isCallExpression(st.expression)&&member(st.expression.expression,'log')&&id(st.expression.expression.expression,'console')
              &&st.expression.arguments.every(a=>pure(a,new Set(fn.parameters.map(p=>p.name.text)),mod)))))return;
          call=call.expression.expression;
        }
        if(ts.isCallExpression(call)&&ts.isPropertyAccessExpression(call.expression)&&id(call.expression.expression,instanceName)
          &&['authenticate','sync'].includes(call.expression.name.text)&&call.arguments.every(a=>pure(a,new Set(),mod)))continue;
      }
      if(match(s,'$db.sequelize=$connection;',new Map(bindings),mod)){if(!registry||instanceExport)return;instanceExport=true;continue;}
      if(match(s,'$db.Sequelize=$Engine;',new Map(bindings),mod)){if(!registry||constructorExport)return;constructorExport=true;continue;}
      if(match(s,'module.exports=$db;',new Map(bindings),mod)){if(!registry||!instanceExport)return;exported=true;continue;}
      return;
    }
    if(!exported||!registry)return;
    if(!version(mod)||Number(version(mod))>5){note(mod,'SEQUELIZE_IMPORT_API_UNSUPPORTED');return;}
    if(!input.nodeSourceInventoryComplete||!Array.isArray(input.nodeSourceInventory)||input.nodeSourceInventory.length>1000){note(mod,'SEQUELIZE_MODEL_INVENTORY_INCOMPLETE');return;}
    const directory=path.posix.dirname(mod.filePath),prefix=directory==='.'?'':directory+'/';
    const inventory=input.nodeSourceInventory.filter(p=>typeof p==='string'&&path.posix.dirname(p)===directory&&path.posix.basename(p)[0]!=='.'&&p!==mod.filePath);
    if(!inventory.length||inventory.length>api.limits.maxFiles)return;
    const names=new Set();
    for(const file of inventory){tick(mod);const target=modules.get(file);if(!target||!file.startsWith(prefix)){note(mod,'SEQUELIZE_MODEL_NOT_PARSED_OR_UNSUPPORTED');return;}
      const name=model(target);if(!name||names.has(name)){note(mod,'SEQUELIZE_MODEL_NOT_PARSED_OR_UNSUPPORTED');return;}names.add(name);evidence.push(loc(target.ast,target,'SEQUELIZE_DEFINE_ONLY_MODEL'));
    }
    const db=object('object'),instance=create(mod,mod.ast);
    instance.ref.origin=evidence.filter(e=>e.kind==='SEQUELIZE_DECLARED_INSTANCE_ORIGIN');
    db.ref.properties.set('sequelize',instance);if(constructorExport)db.ref.properties.set('Sequelize',native('sequelize',mod));
    for(const name of names)db.ref.properties.set(name,unknown());
    note(mod,'SEQUELIZE_INITIALIZATION_SUMMARY_NOT_RUNTIME_EXECUTION');
    api.append(api.result.nodeUses,{ruleId:'JS_CONSTRUCTOR_EFFECT',kind:'INITIALIZATION_SUMMARY_MUST',operation:'SEQUELIZE_REGISTRY_SUMMARY',
      location:loc(mod.ast,mod,'SEQUELIZE_REGISTRY_SUMMARY'),trace:evidence.slice(0,20),limitations:['SOURCE_INVENTORY_NOT_RUNTIME_DIRECTORY','DECLARED_VERSION_NOT_INSTALLED_VERSION','MODEL_API_AND_AUTHORIZATION_NOT_PROVEN']},mod);
    return db;
  }
  return {call,summarize};
}
