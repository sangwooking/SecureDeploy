import ts from 'typescript';

export const VERSION = 'string-context-v2';
const secretPattern = () => /(api[_-]?key|secret|token|accessToken|refreshToken)["']?\s*[:=]\s*["']([^"']{8,})["']/gi;
function credentialShaped(value) {
  if (/^(?:sk-(?:proj-)?[A-Za-z0-9_-]{24,}|gh[pousr]_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{24,}|AKIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{35}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/.test(value)) return true;
  if (value.length < 32) return false;
  const counts=new Map();for (const char of value) counts.set(char,(counts.get(char)??0)+1);
  const entropy=[...counts.values()].reduce((sum,n)=>sum-(n/value.length)*Math.log2(n/value.length),0);
  return counts.size >= 12 && entropy >= 3.5;
}
// Parse only supplied strings. No compiler host, resolution, imports or target execution.
export function classify(files) {
  const output = { version: VERSION, parserVersion: ts.version, files: [] };
  let total = 0;
  const deadline = Date.now() + 5000;
  for (const file of files.slice(0, 100)) {
    const row = { filePath: file.filePath, excludedLines: [], excludedSecretLines: [], requestLines: [], status: 'UNKNOWN' };
    output.files.push(row);
    if (typeof file.content !== 'string' || file.content.length > 100000 || (total += file.content.length) > 1000000) continue;
    if (file.prefixOnly) {
      // Only completed leading comments and complete physical lines are proven.
      // No AST/flow claims are made for a truncated declaration file.
      const comments = (ts.getLeadingCommentRanges(file.content,0) ?? []).filter(c =>
        c.kind === ts.SyntaxKind.MultiLineCommentTrivia ? file.content.slice(c.end-2,c.end) === '*/'
          : /[\r\n]/.test(file.content[c.end] ?? ''));
      let offset = 0, line = 1;
      for (const text of file.content.split('\n')) {
        if (offset + text.length >= file.content.length) break;
        const proven = pattern => {
          const found = [...text.matchAll(pattern)];
          return found.length > 0 && found.every(m => (!m[2] || !credentialShaped(m[2]))
            && comments.some(c => c.pos <= offset+m.index && offset+m.index+m[0].length <= c.end));
        };
        if (proven(/http:\/\//gi)) row.excludedLines.push(line);
        if (proven(secretPattern())) row.excludedSecretLines.push(line);
        offset += text.length+1; line++;
      }
      row.status = 'LEADING_COMMENTS_ONLY'; continue;
    }
    const ast = ts.createSourceFile(file.filePath, file.content, ts.ScriptTarget.Latest, true);
    if (ast.parseDiagnostics.length) continue;
    const nodes = [], comments = [], bindings = new Map();
    let count = 0, limited = false, urlShadowed = false;
    function visit(node) {
      if (++count > 200000 || Date.now() > deadline) { limited = true; return; }
      nodes.push(node);
      for (const pos of [node.pos, node.end]) {
        comments.push(...(ts.getLeadingCommentRanges(file.content, pos) ?? []),
          ...(ts.getTrailingCommentRanges(file.content, pos) ?? []));
      }
      const name = node.name;
      if (name && ts.isIdentifier(name) && (ts.isVariableDeclaration(node) || ts.isParameter(node)
        || ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node) || ts.isImportSpecifier(node)
        || ts.isImportClause(node) || ts.isNamespaceImport(node) || ts.isImportEqualsDeclaration(node) || ts.isBindingElement(node))) {
        bindings.set(name.text, (bindings.get(name.text) ?? 0) + 1);
        if (name.text === 'URL') urlShadowed = true;
      }
      if (ts.isBinaryExpression(node) && ts.isAssignmentOperator(node.operatorToken.kind)
        && /^(?:URL|globalThis\.URL|window\.URL)$/.test(node.left.getText(ast))) urlShadowed = true;
      ts.forEachChild(node, visit);
    }
    visit(ast);
    if (limited) continue;
    const unwrap = n => { while (n && (ts.isParenthesizedExpression(n) || ts.isAsExpression(n) || ts.isNonNullExpression(n))) n = n.expression; return n; };
    function inertProperty(node) {
      const parent = node.parent;
      if (!ts.isPropertyAccessExpression(parent) || parent.expression !== node) return false;
      const usage = parent.parent;
      if (ts.isBinaryExpression(usage) && ts.isAssignmentOperator(usage.operatorToken.kind) && usage.left === parent) return false;
      if (ts.isDeleteExpression(usage) || ts.isPostfixUnaryExpression(usage) || ts.isPrefixUnaryExpression(usage)) return false;
      if (['pathname', 'search', 'hash'].includes(parent.name.text)) return true;
      return ['host', 'hostname', 'protocol', 'origin'].includes(parent.name.text)
        && ts.isBinaryExpression(usage) && [ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken,
          ts.SyntaxKind.EqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsToken].includes(usage.operatorToken.kind);
    }
    function parsingBase(literal) {
      const call = literal.parent;
      if (urlShadowed || !ts.isNewExpression(call) || !ts.isIdentifier(call.expression)
        || call.expression.text !== 'URL' || call.arguments?.length !== 2 || call.arguments[1] !== literal) return false;
      if (inertProperty(call) || ts.isExpressionStatement(call.parent)) return true;
      const decl = call.parent;
      if (!ts.isVariableDeclaration(decl) || !ts.isIdentifier(decl.name)
        || !(decl.parent.flags & ts.NodeFlags.Const) || bindings.get(decl.name.text) !== 1) return false;
      const refs = nodes.filter(n => ts.isIdentifier(n) && n.text === decl.name.text && n !== decl.name
        && !(ts.isPropertyAccessExpression(n.parent) && n.parent.name === n));
      // Unused parsing is inert; aliases, returns, mutation and unknown calls retain warnings.
      return refs.every(inertProperty);
    }
    const literals = nodes.filter(n => ts.isStringLiteralLike(n) || ts.isTemplateHead(n)
      || ts.isTemplateMiddle(n) || ts.isTemplateTail(n));
    function namespace(literal) {
      const attr=literal.parent;
      if (!ts.isJsxAttribute(attr) || attr.initializer !== literal || !['xmlns','xmlns:xlink'].includes(attr.name.getText(ast))) return false;
      const element=attr.parent.parent;
      return (ts.isJsxOpeningElement(element)||ts.isJsxSelfClosingElement(element))
        && ts.isIdentifier(element.tagName) && element.tagName.text === 'svg';
    }
    const byLine = new Map();
    for (const match of file.content.matchAll(/http:\/\//gi)) {
      const pos = match.index, line = ast.getLineAndCharacterOfPosition(pos).line + 1;
      let kind = 'UNKNOWN';
      if (comments.some(c => c.pos <= pos && pos < c.end)) kind = 'COMMENT';
      else {
        const literal = literals.find(n => n.getStart(ast) <= pos && pos < n.end);
        if (literal && ts.isStringLiteralLike(literal) && namespace(literal)) kind = 'NAMESPACE';
        else if (literal && ts.isStringLiteralLike(literal) && parsingBase(literal)) kind = 'PARSING_BASE';
        else if (literal) {
          const parent = literal.parent;
          if (ts.isCallExpression(parent) && parent.arguments[0] === literal
            && /^(?:fetch|axios\.(?:get|post|put|delete|request)|https?\.(?:get|request))$/.test(parent.expression.getText(ast))) kind = 'HTTP_CALL';
        }
      }
      const values = byLine.get(line) ?? []; values.push(kind); byLine.set(line, values);
    }
    for (const [line, kinds] of byLine) {
      if (kinds.every(k => ['COMMENT','PARSING_BASE','NAMESPACE'].includes(k))) row.excludedLines.push(line);
      else if (kinds.includes('HTTP_CALL')) row.requestLines.push(line);
    }
    const secretLines = new Map();
    for (const match of file.content.matchAll(secretPattern())) {
      const pos=match.index, line=ast.getLineAndCharacterOfPosition(pos).line+1;
      let nonCode=comments.some(c => c.pos <= pos && pos < c.end);
      const literal=literals.find(n => n.getStart(ast) <= pos && pos < n.end);
      if (literal) {
        // Quoted object keys are declarations; text inside other strings is not.
        const key=literal.parent.name === literal || ts.isComputedPropertyName(literal.parent)
          || (ts.isElementAccessExpression(literal.parent) && literal.parent.argumentExpression === literal);
        // Embedded JSON/configuration text can itself contain a credential.
        // The UI false match crosses the end of one literal into the next.
        if (!key && pos+match[0].length > literal.end) nonCode=true;
      }
      if (credentialShaped(match[2])) nonCode=false;
      const values=secretLines.get(line) ?? [];values.push(nonCode);secretLines.set(line,values);
    }
    for (const [line,values] of secretLines) if (values.every(Boolean)) row.excludedSecretLines.push(line);
    row.status = 'PARSED';
  }
  return output;
}
