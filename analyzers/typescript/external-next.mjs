import path from 'node:path';

// Audited adapter forwarding only. No SDK configuration, plugin or auth execution.
export function externalNext({ts,input,sourceModule,sourceImports,stable,wrapper,tick,note,limits,loc}) {
  const plans=new WeakMap(),methods=new Set(['GET','POST','PATCH','PUT','DELETE']);
  function plan(mod){
    if(plans.has(mod))return plans.get(mod);
    const vars=new Map(),exports=new Map();
    const add=(map,key,item)=>map.set(key,map.has(key)?null:item);
    for(const s of mod.ast.statements){
      tick(mod);
      if(ts.isVariableStatement(s))for(const d of s.declarationList.declarations){
        const exported=s.modifiers?.some(m=>m.kind===ts.SyntaxKind.ExportKeyword);
        if(ts.isIdentifier(d.name)){
          add(vars,d.name.text,{d,constant:!!(s.declarationList.flags&ts.NodeFlags.Const)});
          if(exported)add(exports,d.name.text,{local:d.name.text,site:s});
        }else if(ts.isObjectBindingPattern(d.name))for(const e of d.name.elements){
          if(!ts.isIdentifier(e.name)||e.dotDotDotToken||e.initializer||e.propertyName&&!ts.isIdentifier(e.propertyName))continue;
          const item={d,constant:!!(s.declarationList.flags&ts.NodeFlags.Const),property:e.propertyName?.text??e.name.text};
          add(vars,e.name.text,item);if(exported)add(exports,e.name.text,{local:e.name.text,site:s});
        }
      }
      if(ts.isExportDeclaration(s)&&!s.isTypeOnly&&s.exportClause&&ts.isNamedExports(s.exportClause))for(const e of s.exportClause.elements){
        if(e.isTypeOnly)continue;
        add(exports,e.name.text,s.moduleSpecifier&&ts.isStringLiteral(s.moduleSpecifier)
          ?{spec:s.moduleSpecifier.text,imported:e.propertyName?.text??e.name.text,site:s}:{local:e.propertyName?.text??e.name.text,site:s});
      }
    }
    const p={vars,exports};plans.set(mod,p);return p;
  }
  function importedAdapter(mod,node){
    if(!ts.isIdentifier(node)||!stable(mod,node.text)||plan(mod).vars.has(node.text)||mod.functions.has(node.text))return false;
    const imp=mod.imports.get(node.text);
    return imp&&!imp.typeOnly&&imp.spec==='better-auth/next-js'&&imp.exported==='toNextJsHandler'
      &&!sourceImports.shadows(mod,imp.spec)&&!sourceImports.externalContractUnknown(mod);
  }
  function supported(mod){
    const manifest=(input.nodeManifests??[]).filter(m=>m.filePath==='package.json'||mod.filePath.startsWith(path.posix.dirname(m.filePath)+'/'))
      .sort((a,b)=>b.filePath.length-a.filePath.length)[0];
    // The declared floor is audited, not proof of the installed/resolved package.
    return /^(?:[~^])?(?:1\.6\.23|1\.7\.12)$/.test(manifest?.['better-auth']??'');
  }
  function safeUses(mod,name){
    return stable(mod,name)&&(mod.syntaxIndex.argumentUses.get(name)??[]).every(u=>
      importedAdapter(mod,u.call.expression)&&u.call.arguments.length===1);
  }
  function targetFunction(mod,node){
    if(ts.isObjectLiteralExpression(node)){
      if(node.properties.length!==1)return;
      const p=node.properties[0];
      if(ts.isShorthandPropertyAssignment(p)&&p.name.text==='handler')node=p.name;
      else if(ts.isPropertyAssignment(p)&&!p.name?.expression&&(p.name.text==='handler'))node=p.initializer;
      else return;
    }
    if(ts.isIdentifier(node)&&!safeUses(mod,node.text))return;
    const fn=wrapper(node,mod,'externalHandler');if(!fn||!safeUses(fn.mod,fn.name))return;
    let contextual=false;
    const scan=n=>{tick(fn.mod);if(n.kind===ts.SyntaxKind.ThisKeyword||n.kind===ts.SyntaxKind.SuperKeyword
      ||ts.isIdentifier(n)&&n.text==='arguments')contextual=true;ts.forEachChild(n,scan);};scan(fn.node);
    return contextual?undefined:fn;
  }
  function expression(mod,node,depth,seen){
    tick(mod);if(!node||depth>limits.maxDepth||seen.has(node)){note(mod,'NEXT_EXTERNAL_BINDING_DEPTH_OR_CYCLE');return;}
    seen=new Set([...seen,node]);
    while(ts.isParenthesizedExpression(node)||ts.isAsExpression(node)||ts.isSatisfiesExpression(node)||ts.isTypeAssertionExpression(node))node=node.expression;
    if(ts.isIdentifier(node))return local(mod,node.text,node,depth+1,seen);
    if(ts.isPropertyAccessExpression(node)&&methods.has(node.name.text)){
      const result=expression(mod,node.expression,depth+1,seen);return result&&!result.method?{...result,method:node.name.text}:undefined;
    }
    if(!ts.isCallExpression(node)||node.arguments.length!==1||!importedAdapter(mod,node.expression))return;
    if(!supported(mod)){note(mod,'NEXT_EXTERNAL_ADAPTER_VERSION_UNKNOWN');return;}
    const fn=targetFunction(mod,node.arguments[0]);
    return {fn,node,mod,trace:[loc(node,mod,'BETTER_AUTH_NEXT_ADAPTER_DECLARATION'),...(fn?[loc(fn.node,fn.mod,'PROJECT_REQUEST_HANDLER')]:[])]};
  }
  function local(mod,name,at,depth,seen){
    tick(mod);if(!safeUses(mod,name)){note(mod,'NEXT_EXTERNAL_BINDING_MUTABLE_OR_ESCAPED');return;}
    const binding=plan(mod).vars.get(name);
    if(plan(mod).vars.has(name)&&(!binding||mod.imports.has(name))){note(mod,'NEXT_EXTERNAL_BINDING_AMBIGUOUS');return;}
    if(binding){
      if(!binding.constant||binding.d.end>=at.pos){note(mod,'NEXT_EXTERNAL_BINDING_ORDER_UNKNOWN');return;}
      const result=expression(mod,binding.d.initializer,depth,seen);
      return result&&binding.property&&!result.method&&methods.has(binding.property)?{...result,method:binding.property}:binding.property?undefined:result;
    }
    const imp=mod.imports.get(name);
    if(imp&&!imp.typeOnly){const target=sourceModule(mod,imp.spec);if(target)return exported(target,imp.exported,depth+1,seen);}
  }
  function exported(mod,name,depth=0,seen=new Set()){
    tick(mod);if(depth>limits.maxDepth){note(mod,'NEXT_EXTERNAL_BINDING_DEPTH_OR_CYCLE');return;}
    const e=plan(mod).exports.get(name);if(!e)return;
    if(e.spec){const target=sourceModule(mod,e.spec),binding=target?exported(target,e.imported,depth+1,seen):undefined;return binding?{...binding,registrationNode:e.site}:undefined;}
    // Export bindings are resolved after their initializer, never by evaluating it.
    const binding=local(mod,e.local,{pos:mod.ast.end+1},depth,seen);
    return binding?{...binding,registrationNode:e.site}:undefined;
  }
  return {exported,methods};
}
