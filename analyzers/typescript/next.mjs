import path from 'node:path';
import {staticHandlerLinks} from './static-handler-links.mjs';

// Conventions are declarations, not proof of a deployed endpoint or invocation.
export function nextEntries({ts, modules, input, tick, note,wrapper,externalHandlers,loc,append,result,exportSupport,sourceModule,limits}) {
  const directive=(statements,name)=>{
    for(const s of statements??[]) {
      if(!ts.isExpressionStatement(s)||!ts.isStringLiteral(s.expression))break;
      if(s.expression.text===name)return true;
    }
    return false;
  };
  const linked=staticHandlerLinks({ts,tick,note,limits});
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
      const rootPages=[...modules.keys()].some(p=>p.startsWith(root+'pages/'));
      const pages=new RegExp('^'+(rootPages?'pages':'(?:src/)?pages')+'/api/.+\\.[jt]sx?$').test(relative);
      if(pages){
        note(mod,'NEXT_PAGES_CONFIG_AND_MIDDLEWARE_NOT_VERIFIED');
        const fn=mod.exports.get('default')??(exportSupport&&sourceModule&&linked.eligible(mod,sourceModule)?exportSupport.functionAt(mod,'default',sourceModule):undefined);
        if(fn&&linked.eligible(mod,sourceModule)&&linked.eligible(fn.mod,sourceModule)&&!fn.node.asteriskToken&&fn.node.parameters.length===2&&fn.node.parameters.every(p=>ts.isIdentifier(p.name)&&!p.dotDotDotToken&&!p.initializer)){
          const registration=mod.ast.statements.find(s=>ts.isExportAssignment(s)||ts.isFunctionDeclaration(s)&&s.modifiers?.some(m=>m.kind===ts.SyntaxKind.DefaultKeyword)||ts.isExportDeclaration(s));
          mod.entries.push({fn,kind:'NEXT_PAGES_HANDLER',registrationNode:registration});
          append(result.nodeUses,{ruleId:'JS_SERVER_ENTRY_CONTEXT',kind:'ENTRY_REGISTERED',operation:'NEXT_PAGES_DEFAULT_HANDLER',location:loc(registration??fn.node,mod,'NEXT_PAGES_REGISTRATION'),trace:[loc(fn.node,fn.mod,'NEXT_PAGES_HANDLER_TARGET',fn)],limitations:['STATIC_PAGES_API_CONVENTION_NOT_DEPLOYMENT_PROOF','MIDDLEWARE_AUTHENTICATION_AND_AUTHORIZATION_NOT_VERIFIED']},mod);
          note(mod,'NEXT_PAGES_DEFAULT_HANDLER_REGISTERED');
        }else note(mod,'NEXT_PAGES_DEFAULT_HANDLER_UNRESOLVED');
      }
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
      const linkedMethods=new Set();
      if(route&&exportSupport&&sourceModule&&mod.ast.statements.some(s=>ts.isExportDeclaration(s)&&!s.isTypeOnly)&&linked.eligible(mod,sourceModule)){
        for(const s of mod.ast.statements){
          if(!ts.isExportDeclaration(s)||s.isTypeOnly||!s.exportClause||!ts.isNamedExports(s.exportClause))continue;
          for(const e of s.exportClause.elements){
            tick(mod);const name=e.name.text;
            if(e.isTypeOnly||!['GET','POST','PATCH','PUT','DELETE','HEAD','OPTIONS'].includes(name)||mod.exports.has(name))continue;
            const fn=exportSupport.functionAt(mod,name,sourceModule);
            if(fn&&linked.eligible(fn.mod,sourceModule)){
              mod.exports.set(name,fn);registrations.set(name,e);linkedMethods.add(name);
              note(mod,'NEXT_STATIC_NAMED_HANDLER_LINK');
              append(result.nodeUses,{ruleId:'JS_SERVER_ENTRY_CONTEXT',kind:'CALLBACK_BOUND',operation:'NEXT_STATIC_NAMED_HANDLER',
                location:loc(e,mod,'NEXT_NAMED_HANDLER_REGISTRATION'),trace:[loc(fn.node,fn.mod,'NEXT_NAMED_HANDLER_TARGET',fn)],
                limitations:['STATIC_REGISTRATION_ONLY','NOT_AUTHENTICATION_OR_AUTHORIZATION_PROOF']},mod);
            }
          }
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
      if(mod.ast.statements.some(s=>ts.isExportDeclaration(s)&&!s.isTypeOnly&&(!s.exportClause||!ts.isNamedExports(s.exportClause)||s.exportClause.elements.some(e=>!e.isTypeOnly&&!linkedMethods.has(e.name.text)&&!(pages&&e.name.text==='default'&&mod.entries.some(x=>x.kind==='NEXT_PAGES_HANDLER'))))))note(mod,'NEXT_REEXPORT_REGISTRATION_NOT_SUPPORTED');
      mod.record.entrypoints=mod.entries.length+opaque;
    } catch {note(mod,'NEXT_REGISTRATION_BUDGET_EXCEEDED');}
  }
}
