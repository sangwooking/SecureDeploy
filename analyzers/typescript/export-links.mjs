// Syntax plans only: no target module evaluation, host lookup, or request-value cache.
export function exportLinks({ts,tick,note,limits}) {
  const plans=new Map();
  function plan(mod) {
    if(plans.has(mod))return plans.get(mod);
    const entries=new Map(),declarations=new Set();
    const add=(name,binding)=>{
      if(entries.has(name)){entries.set(name,null);note(mod,'MODULE_EXPORT_NAME_AMBIGUOUS');}
      else entries.set(name,binding);
    };
    for(const s of mod.ast.statements){
      tick(mod);
      const exported=s.modifiers?.some(m=>m.kind===ts.SyntaxKind.ExportKeyword);
      if(exported&&ts.isFunctionDeclaration(s)&&s.name&&s.body){
        const name=s.modifiers.some(m=>m.kind===ts.SyntaxKind.DefaultKeyword)?'default':s.name.text;
        add(name,{local:s.name.text,origin:'declaration'});
      }
      if(exported&&ts.isVariableStatement(s))for(const d of s.declarationList.declarations)
        if(ts.isIdentifier(d.name))add(d.name.text,{local:d.name.text,origin:'declaration'});
      if(!ts.isExportDeclaration(s))continue;
      declarations.add(s);
      if(s.isTypeOnly)continue;
      if(!s.exportClause||!ts.isNamedExports(s.exportClause)){
        note(mod,'MODULE_WILDCARD_OR_NAMESPACE_EXPORT_NOT_SUPPORTED');continue;
      }
      if(s.moduleSpecifier&&!ts.isStringLiteral(s.moduleSpecifier)){
        note(mod,'MODULE_EXPORT_SPECIFIER_UNKNOWN');continue;
      }
      for(const item of s.exportClause.elements){
        tick(mod);if(item.isTypeOnly)continue;
        const local=item.propertyName?.text??item.name.text;
        add(item.name.text,s.moduleSpecifier?{spec:s.moduleSpecifier.text,imported:local,origin:'forward'}:{local,origin:'local-list'});
      }
    }
    const result={entries,declarations};plans.set(mod,result);return result;
  }
  function stable(mod,name){
    const rootDeclarations=(mod.syntaxIndex?.declarations.get(name)??[]).filter(d=>d.parent===mod.ast
      ||ts.isVariableDeclaration(d)&&d.parent?.parent?.parent===mod.ast);
    return !rootDeclarations.some(d=>ts.isVariableDeclaration(d)&&!(d.parent.flags&ts.NodeFlags.Const))
      &&!mod.syntaxIndex?.writes.has(name)&&!mod.syntaxIndex?.exportWrites?.has(name)
      &&!mod.syntaxIndex?.typeOnly.has(name)&&!mod.syntaxIndex?.argumentReferenceIncomplete.has(name);
  }
  function functionAt(mod,name,target,depth=0,seen=new Map()) {
    tick(mod);
    if(depth>limits.maxDepth){note(mod,'MODULE_EXPORT_DEPTH_LIMIT');return;}
    if(seen.get(mod)?.has(name)){note(mod,'MODULE_EXPORT_CYCLE_UNKNOWN');return;}
    seen=new Map(seen);seen.set(mod,new Set([...(seen.get(mod)??[]),name]));
    const binding=plan(mod).entries.get(name);
    if(!binding){note(mod,'MODULE_EXPORT_BINDING_UNKNOWN');return;}
    if(binding.spec){
      const next=target(mod,binding.spec);if(!next){note(mod,'MODULE_EXPORT_TARGET_NOT_INSPECTED');return;}
      const fn=functionAt(next,binding.imported,target,depth+1,seen);
      if(fn)note(mod,'STATIC_EXPORT_FUNCTION_LINK');return fn;
    }
    if(!stable(mod,binding.local)){note(mod,'MODULE_EXPORT_MUTATION_UNKNOWN');return;}
    const fn=mod.functions.get(binding.local);
    if(fn){note(mod,'STATIC_EXPORT_FUNCTION_LINK');return fn;}
    const imp=mod.imports.get(binding.local);
    if(imp&&!imp.typeOnly){
      const next=target(mod,imp.spec);if(next)return functionAt(next,imp.exported,target,depth+1,seen);
    }
    note(mod,'MODULE_EXPORT_VALUE_NOT_SUPPORTED');
  }
  return {plan,stable,functionAt};
}
