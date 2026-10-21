// Static registration contracts only. Uploaded imports are never loaded.
export function denoEntries({ts, modules, resolve, claimFunction, tick, note, input}) {
  for (const mod of modules.values()) {
    if(!mod.hasDenoSyntax && ![...mod.imports.values()].some(i=>i.exported==='serve'&&i.spec.startsWith('https://deno.land/std@')))continue;
    const shadowed = new Set(), writes = new Set();
    const scan = n => {
      tick(mod);
      if (n.name && ts.isIdentifier(n.name) && (ts.isParameter(n) || ts.isVariableDeclaration(n)
          || ts.isFunctionDeclaration(n) || ts.isClassDeclaration(n) || ts.isImportClause(n)
          || ts.isImportSpecifier(n) || ts.isNamespaceImport(n) || ts.isImportEqualsDeclaration(n)
          || ts.isBindingElement(n))) shadowed.add(n.name.text);
      if (ts.isBinaryExpression(n) && ts.isAssignmentOperator(n.operatorToken.kind)) {
        let base = n.left; while (ts.isPropertyAccessExpression(base) || ts.isElementAccessExpression(base)) base = base.expression;
        if (ts.isIdentifier(base)) writes.add(base.text);
      }
      ts.forEachChild(n, scan);
    };
    try {
      if(mod.syntaxIndex?.bindings){
        for(const name of mod.syntaxIndex.bindings){tick(mod);shadowed.add(name);}
        for(const name of mod.syntaxIndex.writes){tick(mod);writes.add(name);}
      }else scan(mod.ast);
      mod.denoGlobals = !shadowed.has('Deno') && !writes.has('Deno');
      for (const statement of mod.ast.statements) {
        if (!ts.isExpressionStatement(statement) || !ts.isCallExpression(statement.expression)) continue;
        const call = statement.expression, callee = call.expression;
        const native = mod.denoGlobals && ts.isPropertyAccessExpression(callee)
          && ts.isIdentifier(callee.expression) && callee.expression.text === 'Deno' && callee.name.text === 'serve';
        const imported = ts.isIdentifier(callee) ? mod.imports.get(callee.text) : undefined;
        const standard = imported?.exported === 'serve' && !writes.has(callee.text)
          && /^https:\/\/deno\.land\/std@0\.\d+\.\d+\/http\/server\.ts$/.test(imported.spec);
        if (!native && !standard) continue;
        const handler = native ? call.arguments.at(-1) : call.arguments[0];
        let fn;
        if (handler && (ts.isArrowFunction(handler) || ts.isFunctionExpression(handler)) && claimFunction(handler, mod))
          fn = {name: 'handler', node: handler, mod};
        else if (handler && ts.isIdentifier(handler) && !writes.has(handler.text)) fn = resolve(mod, handler.text);
        if (!fn || ![1, 2].includes(call.arguments.length)) { note(mod, 'DENO_REGISTRATION_UNRESOLVED'); continue; }
        mod.entries.push({fn, kind: 'DENO_HTTP_HANDLER', registrationNode: call});
        note(mod, 'DENO_AUTHORIZATION_AND_DEPLOYMENT_NOT_VERIFIED');
        const match=mod.filePath.match(/^(.*supabase\/)functions\/([^/]+)\//);
        if(match) {
          const config=(input.denoConfigs??[]).find(c=>c.filePath===match[1]+'config.toml');
          const flag=config?.status==='PARSED' ? config.verifyJwt?.[match[2]] : undefined;
          note(mod, flag===true?'SUPABASE_VERIFY_JWT_DECLARED_TRUE':flag===false?'SUPABASE_VERIFY_JWT_DECLARED_FALSE':'SUPABASE_VERIFY_JWT_DECLARATION_UNKNOWN');
          note(mod,'SUPABASE_LIVE_AUTHORIZATION_AND_RLS_NOT_VERIFIED');
        }
      }
      mod.record.entrypoints = mod.entries.length;
    } catch { note(mod, 'DENO_REGISTRATION_BUDGET_EXCEEDED'); }
  }
}
