import ts from 'typescript';
import path from 'node:path';

export const VERSION = 'ts-server-v2';
const DEFAULTS = { maxFiles: 100, maxFileChars: 100000, maxTotalChars: 1000000, maxDepth: 3,
  maxSteps: 100000, maxNodes: 200000, maxResults: 200, maxFunctions: 500, timeoutMs: 5000 };
const LIMITATION = '제한된 정적 경로만 확인했습니다. 미들웨어, 동적 호출, 실제 배포·실행·권한 정책은 검증하지 않았습니다.';
const unknown = () => ({ unknown: true, trace: [] });
const value = (tag, trace = [], extra = {}) => ({ tag, trace, ...extra });
const constant = text => value('constant', [], { constant: text });
function union(...values) {
  if (values.length === 1) return values[0];
  const allTrace = values.flatMap(v => v?.trace ?? []).filter((v, i, a) =>
    a.findIndex(w => JSON.stringify(w) === JSON.stringify(v)) === i);
  const trace = allTrace.slice(0, 20);
  const same = values.length && values.every(v => v === values[0]);
  if (same) return values[0];
  return { trace, unknown: allTrace.length > 20 || values.some(v => v?.unknown),
    predicateInput: values.some(v => v?.predicateInput) ? {
      trace: values.flatMap(v => (v?.predicateInput ?? v)?.trace ?? []).slice(0, 20),
      unknown: values.some(v => (v?.predicateInput ?? v)?.unknown)
    } : undefined,
    traceTruncated: allTrace.length > 20 || values.some(v => v?.traceTruncated),
    ref: values.length && values.every(v => v?.ref && v.ref === values[0]?.ref) ? values[0].ref : undefined,
    tag: values.length && values.every(v => v?.tag === values[0]?.tag) ? values[0]?.tag : undefined };
}
const unwrap = node => {
  while (node && (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isNonNullExpression(node)
    || ts.isSatisfiesExpression(node) || ts.isTypeAssertionExpression(node))) node = node.expression;
  return node;
};

// Parse supplied strings only: no compiler host, tsconfig, module loading or target execution.
export function analyze(input, overrides = {}) {
  const limits = { ...DEFAULTS, ...Object.fromEntries(Object.entries(overrides).filter(([k, v]) =>
    k in DEFAULTS && Number.isInteger(v) && v > 0).map(([k, v]) => [k, Math.min(v, DEFAULTS[k])])) };
  const deadline = Date.now() + limits.timeoutMs;
  const result = { schemaVersion: 1, analyzerVersion: VERSION, parserVersion: ts.version,
    status: 'COMPLETE', files: [], findings: [], sqlUses: [], authorizationContexts: [], limitations: [LIMITATION] };
  const modules = new Map();
  let chars = 0, steps = 0, totalFunctions = 0;
  const safeName = text => /^[A-Za-z_$][\w$]{0,79}$/.test(text ?? '') && !/^(?:sk_|gh[pousr]_|AKIA)/.test(text) ? text : '[identifier]';
  const loc = (node, mod, kind, fn) => ({ filePath: mod.filePath,
    line: mod.ast.getLineAndCharacterOfPosition(node.getStart(mod.ast)).line + 1,
    column: mod.ast.getLineAndCharacterOfPosition(node.getStart(mod.ast)).character + 1,
    functionName: safeName(fn?.name ?? 'module'), kind });
  function tick(mod) {
    if (++steps > limits.maxSteps || Date.now() > deadline) {
      mod.record.limitations.add('ANALYSIS_BUDGET_EXCEEDED'); throw new Error('BUDGET');
    }
  }
  function note(mod, reason) { mod.record.limitations.add(reason); }
  function step(v, location, mod) {
    if (!v.trace.length) return v;
    if (v.trace.length < 20) return { ...v, trace: [...v.trace, location] };
    note(mod, 'TRACE_DETAILS_TRUNCATED');
    return { ...v, unknown: true, traceTruncated: true, trace: [v.trace[0], ...v.trace.slice(-18), location] };
  }
  function append(list, item, mod) {
    if (list.length >= limits.maxResults) { note(mod, 'RESULT_LIMIT_EXCEEDED'); return; }
    if (!list.some(existing => JSON.stringify(existing) === JSON.stringify(item))) list.push(item);
  }
  for (const file of input.files ?? []) {
    if (result.files.length >= limits.maxFiles) { result.limitations.push('FILE_COUNT_LIMIT_EXCEEDED'); break; }
    if (!file || typeof file.filePath !== 'string' || typeof file.content !== 'string') continue;
    const filePath = file.filePath.replaceAll('\\', '/');
    if (filePath.startsWith('/') || filePath.split('/').includes('..') || /[\x00-\x1f]/.test(filePath)) continue;
    const record = { filePath, parseStatus: 'PARSED', flowStatus: 'NOT_SUPPORTED', entrypoints: 0,
      functionsAnalyzed: 0, prepareCallSites: 0, tracedPrepareCallSites: 0, limitations: new Set() };
    result.files.push(record);
    if (file.content.length > limits.maxFileChars || chars + file.content.length > limits.maxTotalChars) {
      record.parseStatus = 'LIMIT_EXCEEDED'; record.limitations.add('SOURCE_SIZE_LIMIT_EXCEEDED'); continue;
    }
    chars += file.content.length;
    try {
      const ast = ts.createSourceFile(filePath, file.content, ts.ScriptTarget.Latest, true,
        /\.[jt]sx$/.test(filePath) ? ts.ScriptKind.TSX : /\.js$/.test(filePath) ? ts.ScriptKind.JS : ts.ScriptKind.TS);
      if (ast.parseDiagnostics.length) { record.parseStatus = 'PARSE_FAILED'; record.limitations.add('INVALID_SYNTAX'); continue; }
      const mod = { filePath, ast, record, functions: new Map(), exports: new Map(), imports: new Map(),
        constants: new Map(), declared: new Set(), entries: [], visited: new Set() };
      let nodes = 0;
      const stack = [ast];
      while (stack.length) {
        const n = stack.pop();
        if (++nodes > limits.maxNodes || Date.now() > deadline) throw new Error('BUDGET');
        if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && n.expression.name.text === 'prepare') record.prepareCallSites++;
        ts.forEachChild(n, child => { stack.push(child); });
      }
      const register = (name, node, exported = false) => {
        if (++totalFunctions > limits.maxFunctions) { note(mod, 'FUNCTION_INDEX_LIMIT_EXCEEDED'); return; }
        const fn = { name, node, mod };
        mod.functions.set(name, fn); if (exported) mod.exports.set(name, fn); return fn;
      };
      for (const s of ast.statements) {
        const exported = s.modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword);
        if (ts.isImportDeclaration(s) && ts.isStringLiteral(s.moduleSpecifier)) {
          const spec = s.moduleSpecifier.text;
          if (s.importClause?.name) mod.imports.set(s.importClause.name.text, { spec, exported: 'default' });
          const bindings = s.importClause?.namedBindings;
          if (bindings && ts.isNamedImports(bindings)) for (const e of bindings.elements)
            mod.imports.set(e.name.text, { spec, exported: e.propertyName?.text ?? e.name.text });
          else if (bindings) note(mod, 'NAMESPACE_IMPORT_UNSUPPORTED');
        }
        if (ts.isFunctionDeclaration(s) && s.name && s.body) { mod.declared.add(s.name.text); register(s.name.text, s, exported); }
        if (ts.isVariableStatement(s)) for (const d of s.declarationList.declarations) {
          if (!ts.isIdentifier(d.name)) continue;
          mod.declared.add(d.name.text);
          const init = unwrap(d.initializer);
          if (init && (ts.isArrowFunction(init) || ts.isFunctionExpression(init))) register(d.name.text, init, exported);
          else if (init && (ts.isStringLiteral(init) || ts.isNumericLiteral(init)) && (s.declarationList.flags & ts.NodeFlags.Const)) mod.constants.set(d.name.text, constant(init.text));
        }
      }
      for (const s of ast.statements) {
        if (!ts.isExportAssignment(s)) continue;
        const obj = unwrap(s.expression);
        if (obj && ts.isObjectLiteralExpression(obj)) for (const p of obj.properties) {
          if (p.name?.getText(ast) !== 'fetch') {
            if (p.name?.getText(ast) === 'scheduled') note(mod, 'SCHEDULED_ENTRY_NOT_SUPPORTED');
            continue;
          }
          let fn;
          if (ts.isMethodDeclaration(p)) fn = register('fetch', p);
          else if (ts.isPropertyAssignment(p)) {
            const init = unwrap(p.initializer);
            fn = ts.isIdentifier(init) ? mod.functions.get(init.text)
              : ts.isArrowFunction(init) || ts.isFunctionExpression(init) ? register('fetch', init) : undefined;
          } else if (ts.isShorthandPropertyAssignment(p)) fn = mod.functions.get('fetch');
          if (fn) mod.entries.push({ fn, kind: 'WORKER_FETCH' });
          else note(mod, 'WORKER_ENTRY_UNRESOLVED');
        } else note(mod, 'DEFAULT_EXPORT_FRAMEWORK_UNSUPPORTED');
      }
      if (/(^|\/)functions\//.test(filePath)) for (const [name, fn] of mod.exports)
        if (/^onRequest(?:Get|Post|Put|Patch|Delete|Head|Options)?$/.test(name)) mod.entries.push({ fn, kind: 'PAGES_FUNCTION' });
      record.entrypoints = mod.entries.length;
      if (/\.[jt]sx$/.test(filePath)) note(mod, 'REACT_UI_NOT_SERVER_AUTHORIZATION');
      modules.set(filePath, mod);
    } catch { record.parseStatus = 'LIMIT_EXCEEDED'; record.limitations.add('PARSER_BUDGET_EXCEEDED'); }
  }
  function resolve(mod, name) {
    if (mod.functions.has(name)) return mod.functions.get(name);
    const imported = mod.imports.get(name);
    if (!imported || !imported.spec.startsWith('.')) return undefined;
    const base = path.posix.normalize(path.posix.join(path.posix.dirname(mod.filePath), imported.spec));
    for (const c of [base, base.replace(/\.js$/, '.ts'), `${base}.ts`, `${base}.js`, `${base}/index.ts`, `${base}/index.js`])
      if (modules.get(c)?.exports.has(imported.exported)) return modules.get(c).exports.get(imported.exported);
  }
  function property(base, key, node, state) {
    const { mod, fn } = state;
    if (base.ref?.properties?.has(key)) return { ...base.ref.properties.get(key), unknown: base.ref.unknown || base.ref.properties.get(key).unknown };
    if (base.ref) return { trace: base.ref.trace, unknown: true };
    if (base.tag === 'context') {
      if (key === 'request') return value('request');
      if (key === 'env') return value('env');
      if (key === 'params') return value('route', [loc(node, mod, 'ROUTE_PARAMETER', fn)]);
      if (key === 'data') return value('contextData', [], { unknown: true });
    }
    if (base.tag === 'env') return value('database', [], { unknown: base.unknown });
    if (base.tag === 'contextData' && ['user', 'session', 'principal'].includes(key)) {
      state.context.checks.push(loc(node, mod, 'LOGIN_CONTEXT_REFERENCE', fn));
    }
    if (base.tag === 'request' && key === 'url') return value('urlText', [loc(node, mod, 'REQUEST_URL', fn)], { unknown: base.unknown });
    if (base.tag === 'url' && key === 'searchParams') return value('query', base.trace, { unknown: base.unknown });
    if (base.tag === 'url' && key === 'pathname') return value('input', base.trace, { unknown: base.unknown });
    if (key === 'length' && !base.unknown && ['STRING', 'ARRAY'].includes(base.inputShape)) return value('numeric');
    return { ...base, constant: undefined };
  }
  function bind(name, v, state) {
    if (ts.isIdentifier(name)) state.vars.set(name.text, v);
    else if (ts.isObjectBindingPattern(name)) for (const e of name.elements) {
      if (e.dotDotDotToken) { note(state.mod, 'REST_BINDING_UNSUPPORTED'); bind(e.name, { ...v, unknown: true }, state); }
      else bind(e.name, property(v, e.propertyName?.getText() ?? e.name.getText(), e, state), state);
    } else note(state.mod, 'ARRAY_BINDING_UNSUPPORTED');
  }
  function expr(original, state) {
    const node = unwrap(original);
    if (!node) return unknown();
    const { mod, fn, vars } = state;
    tick(mod);
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) || ts.isNumericLiteral(node)) return constant(node.text);
    if (ts.isIdentifier(node)) return vars.get(node.text) ?? mod.constants.get(node.text) ?? unknown();
    if (ts.isAwaitExpression(node)) return expr(node.expression, state);
    if (ts.isPropertyAccessExpression(node)) return property(expr(node.expression, state), node.name.text, node, state);
    if (ts.isElementAccessExpression(node)) {
      const key = expr(node.argumentExpression, state);
      if (key.constant != null) return property(expr(node.expression, state), key.constant, node, state);
      note(mod, 'DYNAMIC_PROPERTY_UNRESOLVED'); return { ...union(expr(node.expression, state), key), unknown: true };
    }
    if (ts.isTemplateExpression(node)) return step(union(...node.templateSpans.map(s => expr(s.expression, state))), loc(node, mod, 'SQL_STRING_CONSTRUCTION', fn), mod);
    if (ts.isConditionalExpression(node)) { expr(node.condition, state); return union(expr(node.whenTrue, state), expr(node.whenFalse, state)); }
    if (ts.isBinaryExpression(node)) {
      const right = expr(node.right, state);
      if (node.operatorToken.kind === ts.SyntaxKind.EqualsToken || node.operatorToken.kind === ts.SyntaxKind.PlusEqualsToken) {
        const v = node.operatorToken.kind === ts.SyntaxKind.PlusEqualsToken ? union(expr(node.left, state), right) : right;
        if (ts.isIdentifier(node.left)) vars.set(node.left.text, step(v, loc(node.left, mod, 'ASSIGNMENT', fn), mod));
        else {
          note(mod, 'PROPERTY_WRITE_UNRESOLVED');
          if (ts.isPropertyAccessExpression(node.left) || ts.isElementAccessExpression(node.left)) {
            const receiver = expr(node.left.expression, state);
            receiver.unknown = true; receiver.trace = union(receiver, v).trace;
            if (receiver.ref) { receiver.ref.unknown = true; receiver.ref.trace = union(receiver, v).trace; receiver.ref.properties.clear(); }
          }
        }
        return v;
      }
      const left = expr(node.left, state);
      const op = node.operatorToken.kind;
      if ([ts.SyntaxKind.EqualsEqualsToken, ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsToken,
        ts.SyntaxKind.ExclamationEqualsEqualsToken, ts.SyntaxKind.LessThanToken, ts.SyntaxKind.GreaterThanToken,
        ts.SyntaxKind.LessThanEqualsToken, ts.SyntaxKind.GreaterThanEqualsToken, ts.SyntaxKind.InKeyword,
        ts.SyntaxKind.InstanceOfKeyword].includes(op)) {
        const incoming = union(left, right);
        return value('boolean', [], { predicateInput: incoming.predicateInput ?? (incoming.unknown ? incoming : undefined) });
      }
      if ([ts.SyntaxKind.MinusToken, ts.SyntaxKind.AsteriskToken, ts.SyntaxKind.SlashToken, ts.SyntaxKind.PercentToken,
        ts.SyntaxKind.AsteriskAsteriskToken, ts.SyntaxKind.LessThanLessThanToken, ts.SyntaxKind.GreaterThanGreaterThanToken,
        ts.SyntaxKind.GreaterThanGreaterThanGreaterThanToken, ts.SyntaxKind.AmpersandToken, ts.SyntaxKind.BarToken,
        ts.SyntaxKind.CaretToken].includes(op)) return value('numeric');
      const combined = union(left, right);
      return op === ts.SyntaxKind.PlusToken ? step(combined, loc(node, mod, 'SQL_STRING_CONSTRUCTION', fn), mod) : combined;
    }
    if (ts.isObjectLiteralExpression(node)) {
      const properties = new Map();
      let incomplete = false, spread = unknown();
      for (const p of node.properties) {
        if (ts.isPropertyAssignment(p) && !ts.isComputedPropertyName(p.name)) properties.set(p.name.getText().replace(/^['"]|['"]$/g, ''), expr(p.initializer, state));
        else if (ts.isShorthandPropertyAssignment(p)) properties.set(p.name.text, expr(p.name, state));
        else {
          note(mod, 'OBJECT_MEMBER_UNRESOLVED'); incomplete = true;
          if (ts.isSpreadAssignment(p)) spread = union(spread, expr(p.expression, state));
        }
      }
      return value('object', spread.trace, { unknown: incomplete, ref: { properties, unknown: incomplete, trace: spread.trace } });
    }
    if (ts.isArrayLiteralExpression(node)) return union(...node.elements.map(e => expr(e, state)));
    if (ts.isNewExpression(node) || ts.isCallExpression(node)) {
      const callee = unwrap(node.expression), args = (node.arguments ?? []).map(a => expr(a, state));
      let receiverInput;
      if (ts.isIdentifier(callee)) {
        const target = resolve(mod, callee.text);
        if (target && !vars.has(callee.text)) {
          const passed = args.map(a => step(a, loc(node, mod, 'FUNCTION_ARGUMENT', fn), mod));
          return invoke(target, passed, state.depth + 1, state.context, state.stack, state.uncertain);
        }
        if (!vars.has(callee.text) && !mod.imports.has(callee.text) && !mod.declared.has(callee.text)) {
          if (callee.text === 'URL') return value('url', args[0]?.trace ?? [], { unknown: args[0]?.unknown });
          if (callee.text === 'URLSearchParams') return value('query', args[0]?.trace ?? [], { unknown: args[0]?.unknown });
          if (['Number', 'parseInt', 'parseFloat'].includes(callee.text)) {
            state.context.defenses.push(loc(node, mod, 'NUMERIC_CONVERSION', fn)); return value('numeric');
          }
        }
      }
      if (ts.isPropertyAccessExpression(callee)) {
        const receiver = expr(callee.expression, state), method = callee.name.text;
        receiverInput = receiver;
        if (receiver.tag === 'request' && ['json', 'text', 'formData'].includes(method)) return value('input', [loc(node, mod, 'REQUEST_BODY', fn)], { unknown: receiver.unknown, inputShape: method === 'text' ? 'STRING' : undefined });
        if (receiver.tag === 'query' && ['get', 'getAll'].includes(method)) return value('input', receiver.trace.length ? [loc(node, mod, 'QUERY_PARAMETER', fn)] : [], { unknown: receiver.unknown, inputShape: method === 'get' ? 'STRING' : 'ARRAY' });
        if (receiver.tag === 'input' && method === 'get') return receiver;
        if (receiver.tag === 'database' && method === 'prepare') {
          const sql = { ...(args[0] ?? unknown()) };
          if (state.uncertain && sql.trace.length || receiver.unknown) sql.unknown = true;
          const usage = { kind: sql.trace.length ? 'INPUT_IN_QUERY' : sql.unknown ? 'UNRESOLVED_QUERY' : 'STATIC_QUERY',
            location: loc(node, mod, 'D1_PREPARE', fn), trace: sql.trace, defenses: [],
            limitations: sql.unknown ? ['QUERY_HAS_UNRESOLVED_VALUES'] : [], executionObserved: false, executionLocations: [] };
          append(result.sqlUses, usage, mod);
          state.context.resources.push(usage.location);
          if (sql.trace.length) append(result.findings, { ruleId: 'TS_SQL_INPUT_FLOW', kind: 'SQL_INPUT_TO_QUERY',
            confidence: sql.unknown ? 'MEDIUM' : 'HIGH', disposition: 'REVIEW_REQUIRED',
            source: sql.trace[0], sink: usage.location, flow: sql.trace,
            defenses: [], limitations: ['QUERY_CONSTRUCTION_NOT_EXPLOIT_PROOF', 'PATH_FEASIBILITY_NOT_VERIFIED',
              ...(sql.traceTruncated ? ['TRACE_DETAILS_TRUNCATED'] : []), ...(sql.unknown ? ['QUERY_HAS_UNRESOLVED_VALUES'] : [])],
            message: '요청에서 온 값이 데이터베이스 쿼리 문자열에 전달됩니다. 값 바인딩으로 분리할 수 있는지 확인하세요.',
            recommendation: '쿼리 구조를 정적으로 유지하고 외부 값은 prepare(...).bind(...)의 매개변수로 전달한 뒤 재검사하세요.' }, mod);
          return value('statement', [], { usage });
        }
        if (receiver.tag === 'statement' && receiver.usage) {
          if (method === 'bind') {
            receiver.usage.defenses.push(loc(node, mod, 'VALUE_BINDING', fn));
            if (receiver.usage.kind === 'STATIC_QUERY') receiver.usage.kind = 'PARAMETERIZED_QUERY';
            if (receiver.usage.kind === 'INPUT_IN_QUERY') for (const finding of result.findings) {
              if (JSON.stringify(finding.sink) === JSON.stringify(receiver.usage.location)) {
                finding.defenses.push(loc(node, mod, 'VALUE_BINDING', fn));
                if (!finding.limitations.includes('BIND_DOES_NOT_REWRITE_QUERY')) finding.limitations.push('BIND_DOES_NOT_REWRITE_QUERY');
              }
            }
            return receiver;
          }
          if (['first', 'all', 'run', 'raw'].includes(method)) {
            receiver.usage.executionObserved = true;
            if (state.uncertain && !receiver.usage.limitations.includes('EXECUTION_PATH_PARTIAL')) receiver.usage.limitations.push('EXECUTION_PATH_PARTIAL');
            if (receiver.usage.executionLocations.length < 20) receiver.usage.executionLocations.push(loc(node, mod, 'SQL_EXECUTION_CALL', fn));
            return unknown();
          }
        }
        if (method === 'batch' && receiver.tag === 'database') return unknown();
        if (['includes', 'test'].includes(method)) state.context.defenses.push(loc(node, mod, 'VALIDATION_EXPRESSION_PRESENT', fn));
      }
      // Unknown calls preserve input provenance, but do not prove sanitizer correctness or a complete path.
      const incoming = union(...args, ...(receiverInput ? [receiverInput] : []));
      for (const argument of [...args, ...(receiverInput ? [receiverInput] : [])]) if (argument.ref) {
        argument.ref.unknown = true; argument.ref.trace = union(argument, incoming).trace;
        argument.ref.properties.clear();
      }
      note(mod, 'CALL_TARGET_UNRESOLVED');
      return { ...incoming, unknown: true };
    }
    if (ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)) {
      const operand = expr(node.operand, state);
      if (node.operator === ts.SyntaxKind.ExclamationToken)
        return typeof operand.constant === 'boolean' ? constant(!operand.constant)
          : value('boolean', [], { predicateInput: operand.predicateInput ?? (operand.unknown ? operand : undefined) });
      state.context.defenses.push(loc(node, mod, 'NUMERIC_CONVERSION', fn));
      if ([ts.SyntaxKind.PlusPlusToken, ts.SyntaxKind.MinusMinusToken].includes(node.operator) && ts.isIdentifier(node.operand)) vars.set(node.operand.text, value('numeric'));
      return value('numeric');
    }
    if (node.kind === ts.SyntaxKind.TrueKeyword) return constant(true);
    if (node.kind === ts.SyntaxKind.FalseKeyword) return constant(false);
    if (node.kind === ts.SyntaxKind.NullKeyword) return constant(null);
    if (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) { note(mod, 'CALLBACK_FLOW_UNSUPPORTED'); return unknown(); }
    note(mod, 'EXPRESSION_UNSUPPORTED'); return unknown();
  }
  const fork = state => ({ ...state, vars: new Map(state.vars) });
  function mergeVars(state, branches) {
    const merged = new Map();
    for (const key of new Set(branches.flatMap(b => [...b.vars.keys()]))) merged.set(key, union(...branches.map(b => b.vars.get(key) ?? unknown())));
    state.vars = merged;
    state.uncertain = state.uncertain || branches.some(b => b.uncertain);
  }
  // Only inline literal identifier lists/strict comparisons narrow values, never arbitrary validators.
  function allowedIdentifier(condition, truth, depth = 0) {
    if (depth > 3) return;
    let node = unwrap(condition);
    if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.ExclamationToken) {
      truth = !truth; node = unwrap(node.operand);
    }
    if (ts.isBinaryExpression(node)) {
      const op = node.operatorToken.kind;
      if ((op === ts.SyntaxKind.BarBarToken && truth) || (op === ts.SyntaxKind.AmpersandAmpersandToken && !truth)) {
        const a = allowedIdentifier(node.left, truth, depth + 1), b = allowedIdentifier(node.right, truth, depth + 1);
        return a && a === b ? a : undefined;
      }
      if ([ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken].includes(op)
          && truth === (op === ts.SyntaxKind.EqualsEqualsEqualsToken)) {
        const a = unwrap(node.left), b = unwrap(node.right);
        const name = ts.isIdentifier(a) ? a : b, literal = name === a ? b : a;
        if (ts.isIdentifier(name) && ts.isStringLiteral(literal) && /^[A-Za-z_][A-Za-z0-9_]*$/.test(literal.text)) return name.text;
      }
      return;
    }
    if (!truth || !ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression)
        || node.expression.name.text !== 'includes' || node.arguments.length !== 1) return;
    const list = unwrap(node.expression.expression), input = unwrap(node.arguments[0]);
    if (!ts.isArrayLiteralExpression(list) || !ts.isIdentifier(input) || !list.elements.length || list.elements.length > 30
        || !list.elements.every(e => ts.isStringLiteral(e) && /^[A-Za-z_][A-Za-z0-9_]*$/.test(e.text))) return;
    return input.text;
  }
  function refineAllowlist(condition, truth, state) {
    const name = allowedIdentifier(condition, truth);
    if (!name) return;
    state.vars.set(name, value('allowlistedIdentifier'));
    state.context.defenses.push(loc(condition, state.mod, 'LITERAL_IDENTIFIER_ALLOWLIST', state.fn));
  }
  function statement(node, state) {
    const { mod, fn } = state;
    tick(mod);
    if (ts.isBlock(node)) {
      const prior = new Map(state.vars), locals = new Set();
      const names = name => { if (ts.isIdentifier(name)) locals.add(name.text);
        else if (ts.isObjectBindingPattern(name) || ts.isArrayBindingPattern(name)) name.elements.forEach(e => { if (e.name) names(e.name); }); };
      for (const s of node.statements) if (ts.isVariableStatement(s)) {
        if (s.declarationList.flags & ts.NodeFlags.BlockScoped) s.declarationList.declarations.forEach(d => names(d.name));
        else note(mod, 'VAR_HOISTING_PARTIAL');
      }
      const restore = () => { for (const name of locals) { if (prior.has(name)) state.vars.set(name, prior.get(name)); else state.vars.delete(name); } };
      const returns = [];
      for (const s of node.statements) { const r = statement(s, state); returns.push(...r.values); if (r.stops) { restore(); return { values: returns, stops: true }; } }
      restore();
      return { values: returns, stops: false };
    }
    if (ts.isVariableStatement(node)) for (const d of node.declarationList.declarations) {
      const v = expr(d.initializer, state);
      bind(d.name, step(v, loc(d, mod, 'VARIABLE', fn), mod), state);
    }
    else if (ts.isExpressionStatement(node)) expr(node.expression, state);
    else if (ts.isReturnStatement(node)) return { values: [expr(node.expression, state)], stops: true };
    else if (ts.isThrowStatement(node)) { expr(node.expression, state); return { values: [], stops: true }; }
    else if (ts.isIfStatement(node)) {
      const condition = expr(node.expression, state);
      if (condition.constant === true) return statement(node.thenStatement, state);
      if (condition.constant === false) return node.elseStatement ? statement(node.elseStatement, state) : { values: [], stops: false };
      state.context.checks.push(loc(node.expression, mod, 'CONDITIONAL_CHECK', fn));
      const a = fork(state), b = fork(state);
      // A validator we cannot model may restrict this input; do not promote it as an unguarded path.
      const predicate = condition.predicateInput ?? condition;
      if (predicate.unknown && predicate.trace.length) for (const branch of [a, b]) {
        for (const [name, v] of branch.vars) if (v.trace.some(t => predicate.trace.some(c => JSON.stringify(c) === JSON.stringify(t))))
          branch.vars.set(name, { ...v, unknown: true });
      }
      refineAllowlist(node.expression, true, a); refineAllowlist(node.expression, false, b);
      const ar = statement(node.thenStatement, a);
      const br = node.elseStatement ? statement(node.elseStatement, b) : { values: [], stops: false };
      if (ar.stops || br.stops) state.context.defenses.push(loc(node, mod, 'EARLY_EXIT_BRANCH_PRESENT', fn));
      const continuing = [!ar.stops && a, !br.stops && b].filter(Boolean);
      if (continuing.length) mergeVars(state, continuing);
      return { values: [...ar.values, ...br.values], stops: ar.stops && br.stops };
    } else if (ts.isForStatement(node) || ts.isForOfStatement(node) || ts.isForInStatement(node) || ts.isWhileStatement(node) || ts.isDoStatement(node)) {
      note(mod, 'LOOP_FLOW_PARTIAL');
      const branch = { ...fork(state), uncertain: true };
      if (node.initializer && ts.isVariableDeclarationList(node.initializer)) for (const d of node.initializer.declarations) bind(d.name, unknown(), branch);
      if (node.expression) expr(node.expression, branch);
      const r = statement(node.statement, branch); mergeVars(state, [state, branch]); return { ...r, stops: false };
    } else if (ts.isTryStatement(node)) {
      note(mod, 'EXCEPTION_FLOW_PARTIAL');
      const a = { ...fork(state), uncertain: true }, b = { ...fork(state), uncertain: true }, ar = statement(node.tryBlock, a);
      const br = node.catchClause ? statement(node.catchClause.block, b) : { values: [], stops: false };
      mergeVars(state, [a, b]); if (node.finallyBlock) statement(node.finallyBlock, state);
      return { values: [...ar.values, ...br.values], stops: false };
    } else if (ts.isSwitchStatement(node)) {
      note(mod, 'SWITCH_FLOW_PARTIAL'); expr(node.expression, state);
      const branches = [fork(state)]; const returns = [];
      for (const clause of node.caseBlock.clauses) {
        const branch = { ...fork(state), uncertain: true }; branches.push(branch);
        for (const s of clause.statements) { const r = statement(s, branch); returns.push(...r.values); if (r.stops) break; }
      }
      mergeVars(state, branches); return { values: returns, stops: false };
    } else if (![ts.SyntaxKind.EmptyStatement, ts.SyntaxKind.BreakStatement].includes(node.kind)) note(mod, 'STATEMENT_UNSUPPORTED');
    return { values: [], stops: false };
  }
  function invoke(fn, args, depth, context, stack, uncertain = false) {
    const { mod, node } = fn;
    if (depth > limits.maxDepth || stack.has(fn)) {
      note(mod, 'CALL_DEPTH_EXCEEDED'); return { ...union(...args), unknown: true };
    }
    tick(mod); mod.visited.add(fn); mod.record.functionsAnalyzed = mod.visited.size;
    const state = { mod, fn, vars: new Map(), depth, context, uncertain, stack: new Set([...stack, fn]) };
    node.parameters.forEach((p, i) => bind(p.name, args[i] ?? unknown(), state));
    if (!node.body) return unknown();
    if (!ts.isBlock(node.body)) return expr(node.body, state);
    const r = statement(node.body, state);
    return r.values.length ? union(...r.values) : unknown();
  }
  for (const mod of modules.values()) for (const entry of mod.entries) {
    const context = { entry: loc(entry.fn.node, mod, entry.kind, entry.fn), checks: [], defenses: [], resources: [] };
    try {
      invoke(entry.fn, entry.kind === 'WORKER_FETCH' ? [value('request'), value('env')] : [value('context')], 0, context, new Set());
    } catch { note(mod, 'ANALYSIS_BUDGET_EXCEEDED'); }
    for (const field of ['checks', 'defenses', 'resources']) {
      context[field] = context[field].filter((item, i, all) => all.findIndex(other => JSON.stringify(item) === JSON.stringify(other)) === i);
      if (context[field].length > 100) { context[field] = context[field].slice(0, 100); note(mod, 'CONTEXT_DETAILS_LIMIT_EXCEEDED'); }
    }
    append(result.authorizationContexts, { ...context, conclusion: 'NOT_VERIFIED', limitations: [
      '조건 분기만으로 인증·소유권 검증을 입증하지 않습니다.',
      '전역 미들웨어·세션 검증·리소스 소유권과 실패 시 차단 경로를 직접 확인하세요.'
    ] }, mod);
  }
  for (const mod of modules.values()) {
    mod.record.tracedPrepareCallSites = new Set(result.sqlUses.filter(s => s.location.filePath === mod.filePath)
      .map(s => `${s.location.line}:${s.location.column}`)).size;
    if (mod.record.prepareCallSites > mod.record.tracedPrepareCallSites) note(mod, 'PREPARE_CALLS_OUTSIDE_TRACED_FLOW');
    if (mod.visited.size) {
      if (mod.visited.size < mod.functions.size) note(mod, 'UNREACHED_FUNCTIONS_NOT_ANALYZED');
      mod.record.flowStatus = mod.record.limitations.size ? 'PARTIAL' : 'SUPPORTED_FLOW_ANALYZED';
    } else note(mod, 'NO_SUPPORTED_SERVER_ENTRY_OR_CALL');
  }
  result.files.forEach(f => { f.limitations = [...f.limitations].sort(); });
  // Uses are annotated by later bind/run calls, so deduplicate only after those annotations settle.
  result.sqlUses = result.sqlUses.filter((item, i, all) => all.findIndex(other => JSON.stringify(item) === JSON.stringify(other)) === i);
  if (!result.files.length) result.status = 'NOT_APPLICABLE';
  else if (result.files.some(f => f.parseStatus !== 'PARSED' || f.flowStatus !== 'SUPPORTED_FLOW_ANALYZED') || result.limitations.length > 1) result.status = 'PARTIAL';
  return result;
}
