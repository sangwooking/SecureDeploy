// Syntax summaries for function creation only. Never invoke target initializers.
export function wrapperLinks({ts,unwrap,resolve,stable,claimFunction,tick,note,limits,constant,value,loc}) {
  const plans=new WeakMap();
  function plan(fn) {
    if(plans.has(fn.node))return plans.get(fn.node);
    const {node,mod}=fn;tick(mod);
    let body=unwrap(node.body);
    if(ts.isBlock(body)){
      const statements=body.statements.filter(s=>!ts.isEmptyStatement(s));
      body=statements.length===1&&ts.isReturnStatement(statements[0])?unwrap(statements[0].expression):undefined;
    }
    let valid=body&&(ts.isArrowFunction(body)||ts.isFunctionExpression(body))&&!body.asteriskToken&&!node.asteriskToken
      &&!node.modifiers?.some(m=>m.kind===ts.SyntaxKind.AsyncKeyword)
      &&node.parameters.length<=8&&new Set(node.parameters.map(p=>p.name.getText(mod.ast))).size===node.parameters.length
      &&node.parameters.every(p=>ts.isIdentifier(p.name)&&!p.initializer&&!p.dotDotDotToken
        &&!mod.syntaxIndex.writes.has(p.name.text)&&!mod.syntaxIndex.exportWrites.has(p.name.text)
        &&!mod.syntaxIndex.argumentReferenceIncomplete.has(p.name.text));
    if(valid){
      const scan=n=>{
        tick(mod);
        if(n.kind===ts.SyntaxKind.ThisKeyword||n.kind===ts.SyntaxKind.SuperKeyword
          ||ts.isIdentifier(n)&&n.text==='arguments')valid=false;
        ts.forEachChild(n,scan);
      };scan(body);
    }
    const result=valid?body:undefined;plans.set(node,result);return result;
  }
  function binding(mod,name,at) {
    tick(mod);
    const declarations=(mod.syntaxIndex.declarations.get(name)??[]).filter(d=>d.parent===mod.ast
      ||ts.isVariableDeclaration(d)&&d.parent?.parent?.parent===mod.ast);
    if(declarations.length>1||declarations.length&&mod.imports.has(name)||!stable(mod,name)){
      note(mod,'WRAPPER_BINDING_MUTABLE_OR_UNKNOWN');return;
    }
    if(declarations.some(d=>ts.isVariableDeclaration(d)&&d.end>=at.pos)){
      note(mod,'WRAPPER_BINDING_INITIALIZATION_UNKNOWN');return;
    }
    const fn=resolve(mod,name);
    if(fn?.node.asteriskToken){note(mod,'WRAPPER_GENERATOR_NOT_SUPPORTED');return;}
    if(fn&&!stable(fn.mod,fn.name)){note(mod,'WRAPPER_BINDING_MUTABLE_OR_UNKNOWN');return;}
    return fn;
  }
  function build(node,mod,name,depth=0,seen=new Set()) {
    node=unwrap(node);tick(mod);
    if(!node||depth>limits.maxDepth||seen.has(node)){note(mod,'WRAPPER_DEPTH_OR_CYCLE_LIMIT');return;}
    seen=new Set([...seen,node]);
    if(ts.isArrowFunction(node)||ts.isFunctionExpression(node)){
      if(node.asteriskToken){note(mod,'WRAPPER_GENERATOR_NOT_SUPPORTED');return;}
      if(!claimFunction(node,mod))return;
      return {name,node,mod};
    }
    if(ts.isIdentifier(node)){
      return binding(mod,node.text,node);
    }
    if(!ts.isCallExpression(node)||!ts.isIdentifier(unwrap(node.expression))||node.arguments.length>8){
      note(mod,'WRAPPER_TARGET_NOT_SUPPORTED');return;
    }
    const callee=unwrap(node.expression);
    const factory=binding(mod,callee.text,node);
    if(!factory){note(mod,'WRAPPER_FACTORY_SOURCE_UNKNOWN');return;}
    const returned=plan(factory);
    if(!returned){note(mod,'WRAPPER_FACTORY_EFFECTS_OR_STRUCTURE_UNKNOWN');return;}
    const args=[];
    for(const arg of node.arguments){
      tick(mod);const actual=unwrap(arg);
      if(ts.isStringLiteral(actual)||ts.isNumericLiteral(actual))args.push(constant(ts.isNumericLiteral(actual)?Number(actual.text):actual.text));
      else if([ts.SyntaxKind.TrueKeyword,ts.SyntaxKind.FalseKeyword,ts.SyntaxKind.NullKeyword].includes(actual.kind))
        args.push(constant(actual.kind===ts.SyntaxKind.NullKeyword?null:actual.kind===ts.SyntaxKind.TrueKeyword));
      else {
        const fn=build(actual,mod,name+'Handler',depth+1,seen);
        if(!fn){note(mod,'WRAPPER_ARGUMENT_OR_HANDLER_UNKNOWN');return;}
        args.push(value('function',[],{target:fn}));
      }
    }
    if(args.length>factory.node.parameters.length){note(mod,'WRAPPER_ARGUMENT_OR_HANDLER_UNKNOWN');return;}
    const closure=new Map(factory.node.parameters.map((p,i)=>[p.name.text,args[i]??constant(undefined)]));
    if(!claimFunction(returned,factory.mod))return;
    note(mod,'STATIC_WRAPPER_HANDLER_LINK');
    // Captures are fresh per binding, then cloned by the existing request isolator.
    return {name,node:returned,mod:factory.mod,closure,wrapper:true,wrapperLocations:[
      loc(node,mod,'STATIC_WRAPPER_CREATION'),loc(returned,factory.mod,'WRAPPER_FUNCTION_RETURN'),
      ...args.flatMap(a=>a.target?.wrapperLocations??[])].slice(0,20)};
  }
  return {build};
}
