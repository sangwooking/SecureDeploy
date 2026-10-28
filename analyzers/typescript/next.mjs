import path from 'node:path';

// Conventions are declarations, not proof of a deployed endpoint or invocation.
export function nextEntries({ts, modules, input, tick, note,wrapper,externalHandlers,loc,append,result}) {
  const directive=(statements,name)=>{
    for(const s of statements??[]) {
      if(!ts.isExpressionStatement(s)||!ts.isStringLiteral(s.expression))break;
      if(s.expression.text===name)return true;
    }
    return false;
  };
  for(const mod of modules.values()) {
    const manifest=(input.nodeManifests??[]).filter(m=>m.filePath==='package.json'||mod.filePath.startsWith(path.posix.dirname(m.filePath)+'/'))
      .sort((a,b)=>b.filePath.length-a.filePath.length)[0];
    if(!manifest?.next)continue;
    const version=/^[~^]?(\d+)\.(\d+)\.\d+(?:-[\w.-]+)?$/.exec(manifest.next);
    if(!version||+version[1]<13||+version[1]>16||+version[1]===13&&+version[2]<2){note(mod,'NEXT_VERSION_CONTRACT_NOT_SUPPORTED');continue;}
    const root=manifest.filePath==='package.json'?'':path.posix.dirname(manifest.filePath)+'/';
    const relative=mod.filePath.slice(root.length);
    mod.nextContract=true;
    mod.nextResponses=new Set();
    mod.nextEnvironment=false;
    const writes=mod.syntaxIndex?.writes??new Set(),bindings=mod.syntaxIndex?.bindings??new Set();
    try {
      const scan=n=>{
        tick(mod);
        if(n.name&&ts.isIdentifier(n.name)&&(ts.isParameter(n)||ts.isVariableDeclaration(n)||ts.isFunctionDeclaration(n)
            ||ts.isClassDeclaration(n)||ts.isImportClause(n)||ts.isImportSpecifier(n)||ts.isNamespaceImport(n)
            ||ts.isImportEqualsDeclaration(n)||ts.isBindingElement(n)))bindings.add(n.name.text);
        if(ts.isBinaryExpression(n)&&ts.isAssignmentOperator(n.operatorToken.kind)) {
          let base=n.left;while(ts.isPropertyAccessExpression(base)||ts.isElementAccessExpression(base))base=base.expression;
          if(ts.isIdentifier(base))writes.add(base.text);
        }
        if(ts.isFunctionLike(n)&&n.body&&ts.isBlock(n.body)&&directive(n.body.statements,'use server')
            &&n.parent!==mod.ast&&!ts.isVariableDeclaration(n.parent))note(mod,'NEXT_INLINE_SERVER_CLOSURE_NOT_SUPPORTED');
        ts.forEachChild(n,scan);
      };
      if(mod.syntaxIndex?.bindings){
        if(mod.syntaxIndex.nextInlineServerClosure)note(mod,'NEXT_INLINE_SERVER_CLOSURE_NOT_SUPPORTED');
      }else scan(mod.ast);
      mod.nextEnvironment=!bindings.has('process')&&!writes.has('process');
      for(const s of mod.ast.statements)if(ts.isImportDeclaration(s)&&s.moduleSpecifier.text==='next/server'
          &&!s.importClause?.isTypeOnly&&s.importClause?.namedBindings&&ts.isNamedImports(s.importClause.namedBindings))
        for(const e of s.importClause.namedBindings.elements)if(!e.isTypeOnly&&(e.propertyName?.text??e.name.text)==='NextResponse'&&!writes.has(e.name.text))mod.nextResponses.add(e.name.text);
      const client=directive(mod.ast.statements,'use client'),server=directive(mod.ast.statements,'use server');
      const serverOnly=mod.ast.statements.some(s=>ts.isImportDeclaration(s)&&s.moduleSpecifier.text==='server-only');
      if(client){note(mod,'NEXT_CLIENT_BOUNDARY_BUNDLE_NOT_VERIFIED');if(serverOnly||server)note(mod,'NEXT_CONFLICTING_SERVER_CLIENT_DIRECTIVES');continue;}
      if(serverOnly)note(mod,'NEXT_SERVER_ONLY_DECLARATION_NOT_RUNTIME_PROOF');
      if(/^(?:src\/)?pages\/api\//.test(relative))note(mod,'NEXT_PAGES_API_NOT_SUPPORTED');
      const rootApp=[...modules.keys()].some(p=>p.startsWith(root+'app/'));
      const route=new RegExp('^'+(rootApp?'app':'(?:src/)?app')+'/(?:[^/]+/)*route\\.[jt]s$').test(relative);
      if(/^(?:src\/)?app\//.test(relative))note(mod,'NEXT_ROUTING_CONFIG_AND_MIDDLEWARE_NOT_VERIFIED');
      const registrations=new Map();
      let opaque=0;
      if(route&&externalHandlers)for(const method of externalHandlers.methods){
        if(mod.exports.has(method))continue;
        const binding=externalHandlers.exported(mod,method);
        if(!binding?.method)continue;
        const location=loc(binding.registrationNode,mod,'NEXT_EXTERNAL_HANDLER_REGISTRATION');
        append(result.nodeUses,{ruleId:'JS_SERVER_ENTRY_CONTEXT',kind:binding.fn?'CALLBACK_BOUND':'EXTERNAL_IMPLEMENTATION_UNKNOWN',
          operation:'BETTER_AUTH_NEXT_'+method,location,trace:binding.trace,
          limitations:['DECLARED_VERSION_NOT_INSTALLED_LIBRARY','HANDLER_REGISTRATION_NOT_AUTHENTICATION_OR_AUTHORIZATION_PROOF',
            ...(binding.fn?['STATIC_REQUEST_FORWARDING_NOT_RUNTIME_INVOCATION_PROOF']:['SDK_INTERNAL_CALLBACKS_AND_REQUEST_FLOW_NOT_INSPECTED'])]},mod);
        if(binding.fn){
          mod.exports.set(method,{...binding.fn,wrapper:true,wrapperLocations:binding.trace,externalAdapter:true});
          // Keep the request registration at this route, not at the helper body.
          registrations.set(method,binding.registrationNode);
        }else{opaque++;note(mod,'NEXT_EXTERNAL_REGISTERED_HANDLER_BODY_UNKNOWN');}
      }
      if(route&&wrapper)for(const s of mod.ast.statements){
        tick(mod);
        if(!ts.isVariableStatement(s)||!(s.declarationList.flags&ts.NodeFlags.Const)
            ||!s.modifiers?.some(m=>m.kind===ts.SyntaxKind.ExportKeyword))continue;
        for(const d of s.declarationList.declarations){
          if(!ts.isIdentifier(d.name)||!['GET','POST','PATCH','PUT','DELETE','HEAD','OPTIONS'].includes(d.name.text)
              ||mod.exports.has(d.name.text)||!d.initializer)continue;
          if(writes.has(d.name.text)||mod.syntaxIndex.exportWrites.has(d.name.text)){note(mod,'NEXT_MUTABLE_EXPORT_NOT_SUPPORTED');continue;}
          const fn=wrapper(d.initializer,mod,d.name.text);
          if(fn){mod.exports.set(d.name.text,fn);registrations.set(d.name.text,d);}
          else note(mod,'NEXT_WRAPPED_HANDLER_UNKNOWN');
        }
      }
      for(const [name,fn] of mod.exports) {
        if(writes.has(name)){note(mod,'NEXT_MUTABLE_EXPORT_NOT_SUPPORTED');continue;}
        if(route&&['GET','POST','PATCH','PUT','DELETE','HEAD','OPTIONS'].includes(name)) {
          const paramNames=[...relative.matchAll(/\[(?:\[)?(?:\.\.\.)?([A-Za-z_$][\w$]*)\](?:\])?/g)].map(m=>m[1]);
          mod.entries.push({fn,kind:'NEXT_ROUTE_HANDLER',paramNames,registrationNode:registrations.get(name),singleRequestArgument:!!fn.externalAdapter});
          note(mod,'NEXT_ROUTE_AUTHORIZATION_NOT_VERIFIED');
        } else if(server||fn.node.body&&ts.isBlock(fn.node.body)&&directive(fn.node.body.statements,'use server')) {
          if(+version[1]<14||!fn.node.modifiers?.some(m=>m.kind===ts.SyntaxKind.AsyncKeyword)){note(mod,'NEXT_SERVER_FUNCTION_CONTRACT_NOT_SUPPORTED');continue;}
          fn.nextServerReturn=true;
          mod.entries.push({fn,kind:'NEXT_SERVER_FUNCTION'});
          note(mod,'NEXT_SERVER_FUNCTION_INVOCATION_NOT_VERIFIED');
          note(mod,'NEXT_AUTHENTICATION_IS_NOT_RESOURCE_AUTHORIZATION');
        }
      }
      if(mod.ast.statements.some(s=>ts.isExportDeclaration(s)))note(mod,'NEXT_REEXPORT_REGISTRATION_NOT_SUPPORTED');
      mod.record.entrypoints=mod.entries.length+opaque;
    } catch {note(mod,'NEXT_REGISTRATION_BUDGET_EXCEEDED');}
  }
}
