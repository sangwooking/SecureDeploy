// A deliberately closed initialization grammar for newly linked handler modules.
// This does not prove deployment, library initialization, authentication or runtime behavior.
export function staticHandlerLinks({ts,tick,note,limits}) {
  function eligible(mod,resolve,depth=0,seen=new Set()) {
    tick(mod);
    if(depth>limits.maxDepth||seen.has(mod)){note(mod,'STATIC_HANDLER_MODULE_CYCLE_OR_DEPTH_UNKNOWN');return false;}
    const next=new Set([...seen,mod]);
    const unwrap=n=>{while(n&&(ts.isParenthesizedExpression(n)||ts.isAsExpression(n)||ts.isSatisfiesExpression(n)))n=n.expression;return n;};
    for(const s of mod.ast.statements){
      tick(mod);
      if(ts.isExpressionStatement(s)&&ts.isStringLiteral(s.expression)){
        if(s.expression.text==='use client'){note(mod,'STATIC_HANDLER_CLIENT_BOUNDARY_UNSUPPORTED');return false;}continue;
      }
      if(ts.isFunctionDeclaration(s)||ts.isInterfaceDeclaration(s)||ts.isTypeAliasDeclaration(s)||ts.isEmptyStatement(s))continue;
      if(ts.isVariableStatement(s)&&(s.declarationList.flags&ts.NodeFlags.Const)){
        if(s.declarationList.declarations.every(d=>{const v=unwrap(d.initializer);return ts.isIdentifier(d.name)&&v&&(ts.isArrowFunction(v)||ts.isFunctionExpression(v)||ts.isStringLiteralLike(v)||ts.isNumericLiteral(v));}))continue;
      }
      if(ts.isImportDeclaration(s)||ts.isExportDeclaration(s)){
        if(s.isTypeOnly||s.importClause?.isTypeOnly)continue;
        if(ts.isImportDeclaration(s)&&!s.importClause){note(mod,'STATIC_HANDLER_SIDE_EFFECT_IMPORT_UNKNOWN');return false;}
        if(ts.isExportDeclaration(s)&&(!s.exportClause||!ts.isNamedExports(s.exportClause))){note(mod,'STATIC_HANDLER_WILDCARD_EXPORT_UNKNOWN');return false;}
        if(s.moduleSpecifier){
          if(!ts.isStringLiteral(s.moduleSpecifier)){note(mod,'STATIC_HANDLER_MODULE_SPECIFIER_UNKNOWN');return false;}
          const spec=s.moduleSpecifier.text;
          if(spec.startsWith('.')){const target=resolve(mod,spec);if(!target||!eligible(target,resolve,depth+1,next))return false;}
        }
        continue;
      }
      if(ts.isExportAssignment(s)){const v=unwrap(s.expression);if(v&&(ts.isArrowFunction(v)||ts.isFunctionExpression(v)))continue;}
      note(mod,'STATIC_HANDLER_INITIALIZATION_NOT_SUPPORTED');return false;
    }
    return true;
  }
  return {eligible};
}
