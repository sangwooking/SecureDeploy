import ts from 'typescript';
import path from 'node:path';
import { destinationOf, joinDestinations, concatenatedDestination, constructedUrl, unresolvedDestination } from './destination.mjs';
import { credentialShape, sources as exposureSources, uncertain as exposureUncertain, trails as exposureTrails } from './exposure.mjs';
import { nodeServer } from './node-server.mjs';
import { entryState } from './entry-state.mjs';
import { entryContracts } from './entry-contracts.mjs';
import { denoEntries } from './deno.mjs';
import { supabaseAnalysis } from './supabase.mjs';
import { nextEntries } from './next.mjs';
import { analyzePolicies } from './rls.mjs';
import { syntaxIndex, indexSyntax } from './syntax-index.mjs';
import { regexFlow } from './regex-flow.mjs';
import {tsPaths} from './ts-paths.mjs';

export const VERSION = 'ts-server-v26';
const DEFAULTS = { maxFiles: 100, maxFileChars: 100000, maxTotalChars: 1000000, maxDepth: 3,
  maxSteps: 100000, maxNodes: 200000, maxResults: 200, maxFunctions: 500, timeoutMs: 5000 };
const LIMITATION = '제한된 정적 경로만 확인했습니다. 미들웨어, 동적 호출, 실제 배포·실행·권한 정책은 검증하지 않았습니다.';
const unknown = () => ({ unknown: true, trace: [] });
const value = (tag, trace = [], extra = {}) => ({ tag, trace, ...extra });
const constant = text => value('constant', [], { constant: text });
const hasConstant = v => v.tag === 'constant' && Object.hasOwn(v, 'constant') && !v.unknown;
const truth = v => v.tag==='regex-match' ? v.regexMatch?.nonNull&&!v.unknown?true:undefined : hasConstant(v) ? Boolean(v.constant) : v.ref || v.tag === 'function' ? true : undefined;
const nullish = v => hasConstant(v) ? v.constant == null : v.ref || ['function', 'numeric', 'boolean', 'allowlistedIdentifier'].includes(v.tag) ? false : undefined;
function addition(left, right) {
  if (hasConstant(left) && hasConstant(right)) {
    const combined = left.constant + right.constant;
    if (typeof combined !== 'string' || combined.length <= 1000) return { ...constant(combined), exposures: [...exposureSources(left), ...exposureSources(right)], exposureTrail: [...exposureTrails(left),...exposureTrails(right)].slice(0,10) };
  }
  const combined = union(left, right);
  const { constant: ignored, ...withoutConstant } = combined;
  return { ...withoutConstant, responseLocations:undefined, environmentResponses:undefined,
    fixedShellCommandPrefix:hasConstant(left)&&typeof left.constant==='string'&&/^[A-Za-z][A-Za-z0-9_./-]* +$/.test(left.constant)&&right.shellRestricted,
    ...concatenatedDestination(left, right) };
}
function union(...values) {
  if (!values.length) return unknown();
  if (values.length === 1) return values[0];
  const allTrace = values.flatMap(v => v?.trace ?? []).filter((v, i, a) =>
    a.findIndex(w => JSON.stringify(w) === JSON.stringify(v)) === i);
  const trace = allTrace.slice(0, 20);
  const same = values.length && values.every(v => v === values[0]);
  if (same) return values[0];
  const refs = values.filter(v => v?.ref).map(v => v.ref);
  const sameUrl = refs.length && refs[0].identity && values.every(v => v?.ref?.identity === refs[0].identity);
  const mixedRefs = refs.length && !sameUrl && !values.every(v => v?.ref === refs[0]);
  const mergedRef = sameUrl ? { ...refs[0], unknown: refs.some(r => r.unknown),
    checks: Object.fromEntries(Object.entries(refs[0].checks ?? {}).filter(([key, check]) =>
      refs.every(r => JSON.stringify(r.checks?.[key]) === JSON.stringify(check)))) } : refs[0];
  if (sameUrl) {
    mergedRef.queryPartial = refs.some(r => r.queryPartial);
    mergedRef.queryTrace = union(...refs.map(r => ({trace: r.queryTrace ?? []}))).trace;
    mergedRef.properties = new Map([...new Set(refs.flatMap(r => [...r.properties.keys()]))]
      .map(key => [key, union(...refs.map(r => r.properties.get(key) ?? unknown()))]));
  }
  const merged = { trace, unknown: allTrace.length > 20 || values.some(v => v?.unknown) || Boolean(mixedRefs),
    shellRestricted: values.some(v=>v?.trace?.length)&&values.filter(v=>v?.trace?.length).every(v=>v.shellRestricted),
    exposures: values.flatMap(v => exposureSources(v)).slice(0, 20),
    exposureTrail: values.flatMap(v => exposureTrails(v)).slice(0, 10),
    responseLocations: values.flatMap(v => v?.responseLocations ?? []).slice(0, 20),
    environmentResponses: values.flatMap(v => v?.environmentResponses ?? []).slice(0, 20),
    destination: joinDestinations(values),
    predicateInput: values.some(v => v?.predicateInput) ? {
      trace: values.flatMap(v => (v?.predicateInput ?? v)?.trace ?? []).slice(0, 20),
      unknown: values.some(v => (v?.predicateInput ?? v)?.unknown)
    } : undefined,
    traceTruncated: allTrace.length > 20 || values.some(v => v?.traceTruncated),
    ref: refs.length && !mixedRefs ? mergedRef : undefined,
    effects: [...new Set(values.flatMap(v => v?.effects ?? []))],
    target: values.every(v => v?.target && v.target === values[0]?.target) ? values[0].target : undefined,
    tag: values.length && values.every(v => v?.tag === values[0]?.tag) ? values[0]?.tag : undefined };
  if (values.every(v => hasConstant(v) && Object.is(v.constant, values[0].constant))) merged.constant = values[0].constant;
  if (mixedRefs) merged.trace = union(...values.map(v => ({ trace: [...(v.trace ?? []), ...(v.ref?.trace ?? [])], unknown: true }))).trace;
  return merged;
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
    status: 'COMPLETE', files: [], findings: [], sqlUses: [], httpUses: [], exposureUses: [], nodeUses: [], authorizationContexts: [], limitations: [LIMITATION] };
  const modules = new Map();
  let nodeSupport;
  const functionNodes=new WeakSet();
  let chars = 0, steps = 0, totalFunctions = 0;
  let phase='SETUP', astNodes=0;
  const phaseSteps={};
  let jsonReplacerHint=false;
  function charged() {
    if(steps>=limits.maxSteps||Date.now()>deadline)throw Error('SUPABASE_BUDGET');
    steps++;phaseSteps[phase]=(phaseSteps[phase]??0)+1;
  }
  const safeName = text => /^[A-Za-z_$][\w$]{0,79}$/.test(text ?? '') && !/^(?:sk_|gh[pousr]_|AKIA)/.test(text) ? text : '[identifier]';
  const loc = (node, mod, kind, fn) => ({ filePath: mod.filePath,
    line: mod.ast.getLineAndCharacterOfPosition(node.getStart(mod.ast)).line + 1,
    column: mod.ast.getLineAndCharacterOfPosition(node.getStart(mod.ast)).character + 1,
    functionName: safeName(fn?.name ?? 'module'), kind });
  const regexSupport=regexFlow({ts,unwrap,expr,note,tick,loc,step,constant,unknown});
  function tick(mod) {
    try { charged(); } catch {
      mod.record.limitations.add(steps >= limits.maxSteps ? 'ANALYSIS_STEP_BUDGET_EXCEEDED' : 'ANALYSIS_TIME_BUDGET_EXCEEDED');
      mod.record.limitations.add('ANALYSIS_BUDGET_EXCEEDED'); throw new Error('BUDGET');
    }
  }
  function note(mod, reason) { mod.record.limitations.add(reason); }
  function claimFunction(node,mod){if(functionNodes.has(node))return true;if(++totalFunctions>limits.maxFunctions){note(mod,'FUNCTION_INDEX_LIMIT_EXCEEDED');return false;}functionNodes.add(node);return true;}
  function step(v, location, mod) {
    if (exposureSources(v).length) v = { ...v, exposureTrail: [...exposureTrails(v), location].slice(-10) };
    if (!v.trace.length) return v;
    if (v.trace.length < 20) return { ...v, trace: [...v.trace, location] };
    note(mod, 'TRACE_DETAILS_TRUNCATED');
    return { ...v, unknown: true, traceTruncated: true, trace: [v.trace[0], ...v.trace.slice(-18), location] };
  }
  function append(list, item, mod) {
    if (list.length >= limits.maxResults) { note(mod, 'RESULT_LIMIT_EXCEEDED'); return; }
    if (!list.some(existing => JSON.stringify(existing) === JSON.stringify(item))) list.push(item);
  }
  function literal(text, node, mod, fn) {
    return { ...constant(text), exposures: credentialShape(text) ? [loc(node, mod, 'CREDENTIAL_SHAPED_LITERAL', fn)] : [] };
  }
  function observeExposure(v, node, state, kind) {
    if(state.context?.setup)return;
    const origins = exposureSources(v);
    if (!origins.length) return;
    if(kind==='HTTP_RESPONSE_RETURN' && origins.some(o=>['REQUEST_SELECTED_ENVIRONMENT_VALUE','SERVER_SECRET_ENVIRONMENT_VALUE','DECLARED_PUBLIC_ENVIRONMENT_VALUE','ENVIRONMENT_VALUE_UNVERIFIED'].includes(o.kind))
        && !origins.some(o=>['CREDENTIAL_SHAPED_LITERAL','AUTHENTICATION_HEADER','INTERNAL_ERROR_DETAIL','ERROR_DETAIL_CONTEXT_UNKNOWN'].includes(o.kind)))return;
    const location = kind === 'HTTP_RESPONSE_RETURN' && v.responseLocations?.length ? v.responseLocations[0] : loc(node, state.mod, kind, state.fn);
    const unresolved = exposureUncertain(v) || state.uncertain || state.exposureUncertain;
    const supported = origins.filter(o => ['CREDENTIAL_SHAPED_LITERAL', 'AUTHENTICATION_HEADER',
      ...(kind==='LOG_ARGUMENT'?['SERVER_SECRET_ENVIRONMENT_VALUE','REQUEST_SELECTED_ENVIRONMENT_VALUE']:[])].includes(o.kind));
    const errors = kind === 'HTTP_RESPONSE_RETURN' ? origins.filter(o=>o.kind==='INTERNAL_ERROR_DETAIL') : [];
    let status = unresolved ? 'FLOW_UNRESOLVED' : supported.length || errors.length ? 'SENSITIVE_FLOW_CANDIDATE' : 'SENSITIVITY_UNVERIFIED';
    if(kind==='LOG_ARGUMENT' && !supported.length && origins.some(o=>['INTERNAL_ERROR_DETAIL','ERROR_DETAIL_CONTEXT_UNKNOWN'].includes(o.kind)))status='INTERNAL_DIAGNOSTIC_LOG_ONLY';
    const limitations = ['STATIC_EXPOSURE_NOT_RUNTIME_LEAK_PROOF', 'MASKING_LOG_ACCESS_AND_DEPLOYMENT_UNKNOWN',
      ...(location.kind==='EXPRESS_HTTP_RESPONSE'?['EXPRESS_RESPONSE_SERIALIZATION_AND_MIDDLEWARE_NOT_VERIFIED']:[])];
    const trace = [...origins,...exposureTrails(v)].slice(0,20);
    append(result.exposureUses, { kind:location.kind==='EXPRESS_HTTP_RESPONSE'?'HTTP_RESPONSE_SEND':kind, status, location, trace, limitations }, state.mod);
    if (status !== 'SENSITIVE_FLOW_CANDIDATE') return;
    append(result.findings, { ruleId: errors.length ? 'TS_ERROR_DETAIL_EXPOSURE' : 'TS_SENSITIVE_DATA_EXPOSURE', kind: errors.length ? 'CWE-209' : 'CWE-200', confidence: 'HIGH', disposition: 'REVIEW_REQUIRED',
      source: (errors.length ? errors : supported)[0], sink: location, flow: [...trace, location], defenses: [], limitations,
      message: errors.length ? '서버 내부 오류 정보가 사용자에게 전달될 가능성이 있습니다.'
        : kind==='LOG_ARGUMENT'&&supported.some(o=>['SERVER_SECRET_ENVIRONMENT_VALUE','REQUEST_SELECTED_ENVIRONMENT_VALUE'].includes(o.kind))
          ? '서버 비밀 설정 후보가 로그에 전달됩니다. 로그 접근 권한과 마스킹을 확인해 주세요.'
          : '보호해야 할 정보 후보가 서버 응답 또는 로그에 전달되는 경로를 확인해 주세요.',
      recommendation: errors.length ? '사용자 응답에는 일반 오류 메시지와 추적 ID만 반환하고 상세 스택은 접근이 제한된 내부 로그로 분리하세요. 로컬 오류 응답 테스트 후 재검사하세요.' : '응답·로그에서 해당 값을 제거하거나 목적에 맞게 마스킹하세요. 실제 노출이 확인됐다면 자격증명 교체를 검토하고 로컬 테스트와 재검사로 확인하세요. 클라이언트 공개 환경변수로 옮기는 것은 해결이 아닙니다.' }, state.mod);
  }
  function responseBody(v, depth=0, seen=new Set()) {
    if(!v||depth>3||seen.has(v))return {origins:[],trail:[],unresolved:depth>3};
    seen.add(v);
    if(v.tag==='exposureResponse')return {origins:[],trail:[],unresolved:false};
    // One computed data-property always contributes its value to JSON even
    // when its key is unknown. It does not make arbitrary property reads safe.
    if (v?.tag === 'object' && v.ref?.computedKeyOnly && v.ref.properties.size === 1) {
      const child = [...v.ref.properties.values()][0];
      return {origins: exposureSources(child), trail: exposureTrails(child), unresolved: exposureUncertain(child)};
    }
    if(v.ref?.properties){
      const children=[...v.ref.properties.values()].map(c=>responseBody(c,depth+1,seen));
      return {origins:children.flatMap(c=>c.origins).slice(0,20),trail:children.flatMap(c=>c.trail).slice(0,10),
        unresolved:!!v.unknown||!!v.ref.unknown||children.some(c=>c.unresolved)};
    }
    return {origins: exposureSources(v), trail: exposureTrails(v), unresolved: exposureUncertain(v)};
  }
  function observeEnvironmentResponses(returned, state) {
    for (const proof of returned.environmentResponses ?? []) {
      const env = proof.origins.filter(o => ['REQUEST_SELECTED_ENVIRONMENT_VALUE', 'SERVER_SECRET_ENVIRONMENT_VALUE','DECLARED_PUBLIC_ENVIRONMENT_VALUE','ENVIRONMENT_VALUE_UNVERIFIED'].includes(o.kind));
      if (!env.length) continue;
      const sensitive=env.filter(o=>['REQUEST_SELECTED_ENVIRONMENT_VALUE','SERVER_SECRET_ENVIRONMENT_VALUE'].includes(o.kind));
      const serverReturn=proof.location.kind==='SERVER_FUNCTION_RETURN';
      const limitations = ['STATIC_EXPOSURE_NOT_RUNTIME_LEAK_PROOF', 'AUTHORIZATION_AND_DEPLOYMENT_NOT_VERIFIED',
        ...(proof.location.kind==='EXPRESS_HTTP_RESPONSE'?['EXPRESS_RESPONSE_SERIALIZATION_AND_MIDDLEWARE_NOT_VERIFIED']:[]),
        ...(serverReturn?['NEXT_SERVER_FUNCTION_INVOCATION_NOT_VERIFIED']:[]),
        'ENVIRONMENT_CONTENTS_AND_GATEWAY_POLICY_UNKNOWN', 'BRANCH_FEASIBILITY_NOT_VERIFIED'];
      const trace = [...proof.origins, ...proof.trail].filter((v,i,a)=>a.findIndex(w=>JSON.stringify(w)===JSON.stringify(v))===i).slice(0,19);
      const status = proof.unresolved ? 'FLOW_UNRESOLVED' : sensitive.length?'SENSITIVE_FLOW_CANDIDATE':'SENSITIVITY_UNVERIFIED';
      append(result.exposureUses, {kind: serverReturn?'SERVER_FUNCTION_RETURN':proof.location.kind==='EXPRESS_HTTP_RESPONSE'?'HTTP_RESPONSE_SEND':'HTTP_RESPONSE_RETURN', status, location: proof.location, trace, limitations}, state.mod);
      if (!proof.unresolved && sensitive.length) append(result.findings, {ruleId:'TS_SENSITIVE_DATA_EXPOSURE', kind:'CWE-200', confidence:'HIGH',
        disposition:'REVIEW_REQUIRED', source:sensitive[0], sink:proof.location, flow:[...trace, proof.location], defenses:[], limitations,
        message:serverReturn?'서버 환경 설정의 값이 서버 함수 반환값으로 전달됩니다. 클라이언트 호출·권한 문맥을 확인해 주세요.':'서버 환경 설정의 값이 요청 응답에 전달되는 경로를 확인했습니다.',
        recommendation:'환경값 전체를 반환하는 기능을 제거하고 필요한 서버 작업만 제공하세요. 공개 설정과 서버 전용 키를 분리하고, 가짜 값으로 일반 사용자 응답에 서버 비밀값이 포함되지 않는지 확인한 뒤 재검사하세요.'}, state.mod);
    }
  }
  function observeExpressResponse(v,node,state,unresolved=false) {
    if(state.context.setup)return;
    const body=responseBody(v),location=loc(node,state.mod,'EXPRESS_HTTP_RESPONSE',state.fn);
    const serializationUnverified=jsonReplacerHint&&(node.expression.name?.text==='json'||node.expression.name?.text==='send'&&!!v.ref?.properties);
    if(serializationUnverified)note(state.mod,'EXPRESS_JSON_REPLACER_CONTEXT_UNVERIFIED');
    const proof={...body,unresolved:body.unresolved||unresolved||serializationUnverified||state.uncertain||state.exposureUncertain,location};
    const response={tag:'exposureResponse',trace:[],exposures:body.origins,exposureTrail:body.trail,
      unknown:proof.unresolved,responseLocations:[location],environmentResponses:[proof]};
    note(state.mod,'EXPRESS_RESPONSE_SERIALIZATION_AND_MIDDLEWARE_NOT_VERIFIED');
    observeExposure(response,node,state,'HTTP_RESPONSE_RETURN');
    observeEnvironmentResponses(response,state);
  }
  const processObject=x=>ts.isIdentifier(x)&&x.text==='process'||ts.isPropertyAccessExpression(x)
    &&ts.isIdentifier(x.expression)&&x.expression.text==='process'&&x.name.text==='env';
  for (const file of input.files ?? []) {
    if (result.files.length >= limits.maxFiles) { result.limitations.push('FILE_COUNT_LIMIT_EXCEEDED'); break; }
    if (!file || typeof file.filePath !== 'string' || typeof file.content !== 'string') continue;
    const filePath = file.filePath.replaceAll('\\', '/');
    if (filePath.startsWith('/') || filePath.split('/').includes('..') || /[\x00-\x1f]/.test(filePath)) continue;
    const record = { filePath, parseStatus: 'PARSED', flowStatus: 'NOT_SUPPORTED', entrypoints: 0,
      functionsAnalyzed: 0, prepareCallSites: 0, tracedPrepareCallSites: 0, httpCallSites: 0, tracedHttpCallSites: 0, limitations: new Set() };
    result.files.push(record);
    if (file.content.length > limits.maxFileChars || chars + file.content.length > limits.maxTotalChars) {
      record.parseStatus = 'LIMIT_EXCEEDED'; record.limitations.add('SOURCE_SIZE_LIMIT_EXCEEDED'); continue;
    }
    chars += file.content.length;
    try {
      const ast = ts.createSourceFile(filePath, file.content, ts.ScriptTarget.Latest, true,
        /\.[jt]sx$/.test(filePath) ? ts.ScriptKind.TSX : /\.[cm]?js$/.test(filePath) ? ts.ScriptKind.JS : ts.ScriptKind.TS);
      if (ast.parseDiagnostics.length) { record.parseStatus = 'PARSE_FAILED'; record.limitations.add('INVALID_SYNTAX'); continue; }
      const mod = { filePath, ast, record, functions: new Map(), exports: new Map(), imports: new Map(),
        constants: new Map(), declared: new Set(), entries: [], visited: new Set(), syntaxIndex:syntaxIndex() };
      let nodes = 0;
      const stack = [ast];
      while (stack.length) {
        const n = stack.pop();
        if (++nodes > limits.maxNodes || Date.now() > deadline) throw new Error('BUDGET');
        astNodes++;
        indexSyntax(ts,n,mod.syntaxIndex);
        // A visible serialization hook prevents assuming the default JSON contract.
        // Its receiver/app relationship is not resolved, so keep this conservative and order independent.
        if(ts.isCallExpression(n)&&ts.isPropertyAccessExpression(n.expression)&&n.expression.name.text==='set'
            &&ts.isStringLiteral(n.arguments[0])&&n.arguments[0].text==='json replacer'&&n.arguments[1]
            &&n.arguments[1].kind!==ts.SyntaxKind.NullKeyword)jsonReplacerHint=true;
        if((ts.isCallExpression(n)||ts.isNewExpression(n))&&(n.arguments??[]).some(processObject))mod.processEscaped=true;
        if((ts.isCallExpression(n)||ts.isNewExpression(n))&&(n.arguments??[]).some(x=>ts.isIdentifier(x)&&x.text==='console'))mod.consoleMutated=true;
        if(ts.isDeleteExpression(n)||(ts.isPrefixUnaryExpression(n)||ts.isPostfixUnaryExpression(n))
            &&[ts.SyntaxKind.PlusPlusToken,ts.SyntaxKind.MinusMinusToken].includes(n.operator)){
          let x=n.expression??n.operand;while(x&&(ts.isPropertyAccessExpression(x)||ts.isElementAccessExpression(x)))x=x.expression;
          if(x&&ts.isIdentifier(x)&&x.text==='process')mod.processEscaped=true;
          if(x&&ts.isIdentifier(x)&&x.text==='console')mod.consoleMutated=true;
        }
        if(ts.isIdentifier(n)&&n.text==='Deno')mod.hasDenoSyntax=true;
        if(ts.isIdentifier(n)&&['from','createClient'].includes(n.text))mod.hasSupabaseSyntax=true;
        if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && n.expression.name.text === 'prepare') record.prepareCallSites++;
        if (ts.isCallExpression(n) && (ts.isIdentifier(n.expression) && n.expression.text === 'fetch'
            || ts.isPropertyAccessExpression(n.expression) && n.expression.name.text === 'fetch')) record.httpCallSites++;
        ts.forEachChild(n, child => { stack.push(child); });
      }
      mod.syntaxIndex.nodes.sort((a,b)=>a.pos-b.pos||b.end-a.end);
      mod.syntaxIndex.dependencies.sort((a,b)=>a.pos-b.pos);
      const register = (name, node, exported = false, lexical = true) => {
        if (!claimFunction(node,mod)) return;
        const fn = { name, node, mod };
        mod.functions.set(lexical ? name : Symbol(name), fn); if (exported) mod.exports.set(name, fn); return fn;
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
          else if (init && (ts.isStringLiteral(init) || ts.isNumericLiteral(init)) && (s.declarationList.flags & ts.NodeFlags.Const)) mod.constants.set(d.name.text, literal(ts.isNumericLiteral(init) ? Number(init.text) : init.text, init, mod));
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
          // An object method is not a lexical binding of the global fetch function.
          if (ts.isMethodDeclaration(p)) fn = register('fetch', p, false, false);
          else if (ts.isPropertyAssignment(p)) {
            const init = unwrap(p.initializer);
            fn = ts.isIdentifier(init) ? mod.functions.get(init.text)
              : ts.isArrowFunction(init) || ts.isFunctionExpression(init) ? register('fetch', init, false, false) : undefined;
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
  const sourceImports=tsPaths({ts,input,modules,note,charge:()=>{
    charged();if(astNodes>=limits.maxNodes)throw Error('AST_CONFIG_LIMIT');astNodes++;
  }});
  function resolve(mod, name) {
    if (mod.functions.has(name)) return mod.functions.get(name);
    const imported = mod.imports.get(name);
    if (!imported) return undefined;
    if(!imported.spec.startsWith('.'))return sourceImports.target(mod,imported.spec)?.exports.get(imported.exported);
    const base = path.posix.normalize(path.posix.join(path.posix.dirname(mod.filePath), imported.spec));
    for (const c of [base, base.replace(/\.js$/, '.ts'), `${base}.ts`, `${base}.js`, `${base}/index.ts`, `${base}/index.js`])
      if (modules.get(c)?.exports.has(imported.exported)) return modules.get(c).exports.get(imported.exported);
  }
  function property(base, key, node, state) {
    const { mod, fn } = state;
    if(base.externalObject&&['__proto__','prototype','constructor'].includes(key))return {...unknown(),trace:base.trace};
    if(state.nodeMode){const supported=regexSupport.property(base,key,node,state);if(supported)return supported;}
    if(state.nodeMode){const supported=nodeSupport.property(base,key,node,state);if(supported)return supported;}
    if(['error-object','caught-error'].includes(base.tag) && key==='stack'){
      const unresolved=base.unknown||base.ref?.unknown;
      return value('error-detail',[],{unknown:unresolved,exposures:[...exposureSources(base),loc(node,mod,unresolved?'ERROR_DETAIL_CONTEXT_UNKNOWN':'INTERNAL_ERROR_DETAIL',fn)],exposureTrail:exposureTrails(base)});
    }
    if (base.ref?.http && base.tag === 'url') {
      const uncertain = base.unknown || base.ref.unknown;
      if (key === 'searchParams') return value('query', base.trace, { unknown: uncertain, ref: base.ref });
      if (key === 'href') return value('urlText', base.trace, { unknown: uncertain, destination: destinationOf(base) });
      if (base.ref.properties.has(key)) return { ...base.ref.properties.get(key), unknown: uncertain || base.ref.properties.get(key).unknown };
      if (['hostname', 'host', 'protocol', 'pathname', 'search', 'hash', 'port'].includes(key))
        return value('input', base.trace, { unknown: uncertain, urlMember: key, destination: unresolvedDestination() });
      return { ...unknown(), trace: base.trace };
    }
    if (base.tag === 'outboundRequest' && key === 'url') return value('urlText', base.trace, { destination: destinationOf(base), unknown: base.unknown || base.ref?.unknown });
    if (base.ref?.properties?.has(key)) return { ...base.ref.properties.get(key), unknown: base.ref.unknown || base.ref.properties.get(key).unknown };
    if (base.ref) return base.ref.unknown ? { trace: base.ref.trace, unknown: true } : constant(undefined);
    if (base.tag === 'context') {
      if (key === 'request') return value('request');
      if (key === 'env') return value('env');
      if (key === 'params') return value('route', [loc(node, mod, 'ROUTE_PARAMETER', fn)]);
      if (key === 'data') return value('contextData', [], { unknown: true });
    }
    if (base.tag === 'env') return value('database', [], { unknown: base.unknown, exposures: [loc(node, mod, 'ENVIRONMENT_VALUE_UNVERIFIED', fn)] });
    if (base.tag === 'contextData' && ['user', 'session', 'principal'].includes(key)) {
      state.context.checks.push(loc(node, mod, 'LOGIN_CONTEXT_REFERENCE', fn));
    }
    if (base.tag === 'request' && key === 'url') return value('urlText', [loc(node, mod, 'REQUEST_URL', fn)], { unknown: base.unknown, destination: unresolvedDestination() });
    if (base.tag === 'request' && key === 'headers') return value('headers', [], { unknown: base.unknown || state.context.headersMutated });
    if (base.tag === 'request' && key === 'nextUrl' && state.context.entry.kind==='NEXT_ROUTE_HANDLER')
      return value('url', [loc(node,mod,'REQUEST_URL',fn)], {ref:{http:unresolvedDestination(),properties:new Map(),trace:[],unknown:false}});
    if (base.tag === 'nextContext' && key === 'params') return value('object',[],{ref:{properties:new Map(
      (base.paramNames??[]).map(name=>[name,value('input',[loc(node,mod,'ROUTE_PARAMETER',fn)])])),unknown:false,trace:[]}});
    if (base.tag === 'url' && key === 'searchParams') return value('query', base.trace, { unknown: base.unknown });
    if (base.tag === 'url' && key === 'pathname') return value('input', base.trace, { unknown: base.unknown });
    if (key === 'length' && !base.unknown && ['STRING', 'ARRAY'].includes(base.inputShape)) return value('numeric');
    return { ...base, constant: undefined };
  }
  function invalidateNodeReference(ref,state,incoming,seen=new Set()) {
    if(!ref||seen.has(ref))return;
    tick(state.mod);seen.add(ref);
    if(ref.nodeIdentity)state.nodeMutations?.add(ref.nodeIdentity);
    if(ref.originParent)invalidateNodeReference(ref.originParent,state,incoming,seen);
    for(const child of ref.properties.values())invalidateNodeReference(child.ref,state,incoming,seen);
    ref.unknown=true;ref.trace=union({trace:ref.trace??[]},incoming).trace;ref.properties.clear();
  }
  function bind(name, v, state) {
    if (ts.isIdentifier(name)) state.vars.set(name.text, v);
    else if (ts.isObjectBindingPattern(name)) for (const e of name.elements) {
      if (e.dotDotDotToken) { note(state.mod, 'REST_BINDING_UNSUPPORTED'); bind(e.name, { ...v, unknown: true }, state); }
      else {
        const keyNode = e.propertyName;
        const key = keyNode && ts.isComputedPropertyName(keyNode) ? expr(keyNode.expression, state)
          : constant(keyNode?.text ?? e.name.getText());
        if (!hasConstant(key)) note(state.mod, 'DYNAMIC_BINDING_KEY_UNRESOLVED');
        const selected = hasConstant(key) ? property(v, String(key.constant), e, state) : { ...union(v, key), unknown: true };
        bind(e.name, defaultValue(selected, e.initializer, state), state);
      }
    } else note(state.mod, 'ARRAY_BINDING_UNSUPPORTED');
  }
  function numeric(inputs, node, state) {
    state.context.defenses.push(loc(node, state.mod, 'NUMERIC_CONVERSION', state.fn));
    const incoming = union(...inputs);
    if (inputs.some(v => v.unknown || v.ref)) {
      note(state.mod, 'NUMERIC_COERCION_PARTIAL');
      return { ...incoming, tag: 'numeric', unknown: true, constant: undefined };
    }
    return value('numeric');
  }
  function referenceOf(original, state) {
    const node = unwrap(original), { mod, fn } = state;
    if (ts.isIdentifier(node)) return {
      read: () => expr(node, state),
      write: (v, target) => target.vars.set(node.text, step(v, loc(node, mod, 'ASSIGNMENT', fn), mod))
    };
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const receiver = expr(node.expression, state);
      const key = ts.isPropertyAccessExpression(node) ? constant(node.name.text) : expr(node.argumentExpression, state);
      return {
        read: () => hasConstant(key) ? property(receiver, String(key.constant), node, state) : { ...union(receiver, key), unknown: true },
        write: (v, target) => {
          if(nodeSupport?.write(receiver,key,v,target))return;
          if (receiver.ref?.http && receiver.tag === 'url') {
            note(mod, 'URL_PROPERTY_WRITE');
            const ref = target.forkRefs?.get(receiver.ref) ?? receiver.ref;
            if (hasConstant(key) && ['pathname', 'search', 'hash'].includes(key.constant)) {
              ref.properties.set(key.constant, v.ref ? { ...unknown(), trace: v.trace } : v);
              if (key.constant === 'search') { ref.queryTrace = v.trace; ref.queryPartial = true; }
              return;
            }
            ref.unknown = true; ref.checks = {}; ref.trace = union({ trace: ref.trace }, v).trace;
            note(mod, 'URL_MUTATION_UNRESOLVED'); return;
          }
          note(mod, 'PROPERTY_WRITE_UNRESOLVED');
          if(target.nodeMode&&target.context.setup&&receiver.externalObject&&hasConstant(key)
              &&!['__proto__','prototype','constructor'].includes(String(key.constant))&&!v.ref&&!v.target&&!v.native&&!v.trace.length){
            // Unknown external data stays unknown. This is not a proof of setter
            // behavior; it must not erase an unrelated, observed request path.
            receiver.externalObject.unverified=true;
            note(mod,'EXTERNAL_PROPERTY_WRITE_SCOPED_UNKNOWN');return;
          }
          const ref = target.forkRefs?.get(receiver.ref) ?? receiver.ref;
          if(target.nodeMode&&ref){invalidateNodeReference(ref,target,v);return;}
          if (ref) { ref.unknown = true; ref.trace = union({ trace: ref.trace }, v).trace; ref.properties.clear(); }
          else target.uncertain = true;
        }
      };
    }
    note(mod, 'ASSIGNMENT_TARGET_UNSUPPORTED');
    return { read: () => unknown(), write: () => { state.uncertain = true; } };
  }
  function defaultValue(selected, initializer, state) {
    if (!initializer || hasConstant(selected) && selected.constant !== undefined) return selected;
    if (hasConstant(selected)) return expr(initializer, state);
    const skipped = fork(state), taken = fork(state);
    const fallback = expr(initializer, taken);
    mergeVars(state, [skipped, taken]);
    return union(selected, fallback);
  }
  const writePlans = new WeakMap();
  function writtenNames(node, state) {
    tick(state.mod);
    if (writePlans.has(node)) return writePlans.get(node);
    const effects = new Set();
    const scan = n => {
      tick(state.mod);
      if (ts.isBinaryExpression(n) && n.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
          && n.operatorToken.kind <= ts.SyntaxKind.LastAssignment) {
        let target = unwrap(n.left);
        while (ts.isPropertyAccessExpression(target) || ts.isElementAccessExpression(target)) target = unwrap(target.expression);
        if (ts.isIdentifier(target)) effects.add(target.text);
      }
      if ((ts.isPrefixUnaryExpression(n) || ts.isPostfixUnaryExpression(n))
          && [ts.SyntaxKind.PlusPlusToken, ts.SyntaxKind.MinusMinusToken].includes(n.operator) && ts.isIdentifier(n.operand)) effects.add(n.operand.text);
      ts.forEachChild(n, scan);
    };
    scan(node);
    const plan=Object.freeze([...effects]);writePlans.set(node,plan);return plan;
  }
  function invalidateWrites(names, state, incoming = unknown()) {
    for (const name of names) {
      const old = state.vars.get(name);
      if (!old) continue;
      state.vars.set(name, { ...union(old, incoming), unknown: true, constant: undefined, urlPrefix: undefined, destination: unresolvedDestination() });
      if(state.nodeMode&&old.ref){invalidateNodeReference(old.ref,state,incoming);continue;}
      if (old.ref) { old.ref.unknown = true; old.ref.trace = union({ trace: old.ref.trace }, incoming).trace; old.ref.properties.clear(); }
    }
  }
  function unsupportedClosure(node, state) {
    note(state.mod, 'CALLBACK_FLOW_UNSUPPORTED');
    return { ...unknown(), effects: writtenNames(node, state) };
  }
  function expr(original, state) {
    const node = unwrap(original);
    if (!node) return unknown();
    const { mod, fn } = state;
    tick(mod);
    if ((node.flags & ts.NodeFlags.OptionalChain) && state.optionalNode !== node) {
      note(mod, 'OPTIONAL_CHAIN_PARTIAL');
      const skipped = fork(state), taken = { ...fork(state), optionalNode: node, uncertain: true };
      const result = expr(node, taken);
      mergeVars(state, [skipped, taken]);
      return { ...union(result, constant(undefined)), unknown: true };
    }
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return literal(node.text, node, mod, fn);
    if (ts.isNumericLiteral(node)) return constant(Number(node.text));
    if(state.nodeMode&&ts.isRegularExpressionLiteral(node))return regexSupport.pattern(node,state);
    if(state.nodeMode&&ts.isTypeOfExpression(node)){expr(node.expression,state);return value('type-name');}
    if(node.kind===ts.SyntaxKind.ThisKeyword&&state.nodeMode)return state.thisValue??unknown();
    if (ts.isIdentifier(node)) {
      const found = state.vars.get(node.text) ?? mod.constants.get(node.text);
      if (found?.uninitialized) { note(mod, 'LEXICAL_READ_BEFORE_INITIALIZATION'); return unknown(); }
      if (found) return found;
      const target = resolve(mod, node.text);
      if (target) return value('function', [], { target });
      if (node.text === 'undefined' && !mod.declared.has(node.text) && !mod.imports.has(node.text)) return constant(undefined);
      return unknown();
    }
    if (ts.isAwaitExpression(node)) return expr(node.expression, state);
    const environment=serverEnvironmentValue(node,state);
    if(environment)return environment;
    if (ts.isPropertyAccessExpression(node)) return property(expr(node.expression, state), node.name.text, node, state);
    if (ts.isElementAccessExpression(node)) {
      const base = expr(node.expression, state);
      const key = expr(node.argumentExpression, state);
      if (hasConstant(key)) return property(base, String(key.constant), node, state);
      note(mod, 'DYNAMIC_PROPERTY_UNRESOLVED'); return { ...union(base, key), unknown: true };
    }
    if (ts.isTemplateExpression(node)) {
      let combined = constant(node.head.text);
      for (const span of node.templateSpans) combined = addition(addition(combined, expr(span.expression, state)), constant(span.literal.text));
      return step(combined, loc(node, mod, 'SQL_STRING_CONSTRUCTION', fn), mod);
    }
    if (ts.isConditionalExpression(node)) {
      const condition = expr(node.condition, state), decision = truth(condition);
      if (decision !== undefined) return expr(decision ? node.whenTrue : node.whenFalse, state);
      const a = fork(state), b = fork(state);
      guardBranches(node.condition, condition, a, b);
      const left = expr(node.whenTrue, a), right = expr(node.whenFalse, b);
      mergeVars(state, [a, b]); return union(left, right);
    }
    if (ts.isBinaryExpression(node)) {
      const op = node.operatorToken.kind;
      const assignment = op >= ts.SyntaxKind.FirstAssignment && op <= ts.SyntaxKind.LastAssignment;
      // Capture the reference (and old compound-assignment value) before RHS effects.
      const reference = assignment ? referenceOf(node.left, state) : undefined;
      const left = op === ts.SyntaxKind.EqualsToken ? undefined : assignment ? reference.read() : expr(node.left, state);
      const logical = new Map([[ts.SyntaxKind.AmpersandAmpersandToken, 'AND'], [ts.SyntaxKind.BarBarToken, 'OR'],
        [ts.SyntaxKind.QuestionQuestionToken, 'NULLISH'], [ts.SyntaxKind.AmpersandAmpersandEqualsToken, 'AND'],
        [ts.SyntaxKind.BarBarEqualsToken, 'OR'], [ts.SyntaxKind.QuestionQuestionEqualsToken, 'NULLISH']]).get(op);
      if (logical) {
        const condition = logical === 'NULLISH' ? nullish(left) : truth(left);
        const takeRight = condition === undefined ? undefined : logical === 'OR' ? !condition : condition;
        if (takeRight === false) return left;
        if (takeRight === true) {
          const right = expr(node.right, state); if (assignment) reference.write(right, state); return right;
        }
        const fallback=unwrap(node.right);
        if(state.nodeMode&&!assignment&&regexSupport.pureMatch(node.right,state)){
          // A supported literal match has no mutable lastIndex or target-code effects.
          // Preserve the heap rather than merging unrelated cloned capabilities.
          const evaluated={...state,vars:new Map(state.vars)};
          if(logical!=='NULLISH')regexSupport.refine(node.left,logical==='AND',evaluated);
          const right=expr(node.right,evaluated);
          return union(left,right);
        }
        if(state.nodeMode&&!assignment&&(ts.isStringLiteral(fallback)||ts.isNumericLiteral(fallback)
            ||ts.isNoSubstitutionTemplateLiteral(fallback)||[ts.SyntaxKind.TrueKeyword,ts.SyntaxKind.FalseKeyword,ts.SyntaxKind.NullKeyword].includes(fallback.kind))) {
          // A primitive RHS cannot mutate state. Keep the uncertain result,
          // without forking and losing unrelated object capabilities.
          return union(left,expr(node.right,state));
        }
        const skip = fork(state), take = fork(state);
        if (logical !== 'NULLISH') {
          if (logical === 'AND') guardBranches(node.left, left, take, skip);
          else guardBranches(node.left, left, skip, take);
        }
        const right = expr(node.right, take);
        if (assignment) reference.write(right, take);
        mergeVars(state, [skip, take]);
        return union(left, right);
      }
      const right = expr(node.right, state);
      if(state.nodeMode&&[ts.SyntaxKind.EqualsEqualsEqualsToken,ts.SyntaxKind.ExclamationEqualsEqualsToken].includes(op)&&hasConstant(left)&&hasConstant(right))
        return constant((op===ts.SyntaxKind.EqualsEqualsEqualsToken)===Object.is(left.constant,right.constant));
      if(state.nodeMode&&op===ts.SyntaxKind.InstanceOfKeyword&&state.constructing&&!right?.unknown&&left?.ref===state.thisValue?.ref&&right?.target===state.thisValue?.constructorTarget)return constant(true);
      if (op === ts.SyntaxKind.EqualsToken) { reference.write(right, state); return right; }
      if (op === ts.SyntaxKind.CommaToken) return right;
      if (op === ts.SyntaxKind.PlusEqualsToken) {
        const combined = step(addition(left, right), loc(node, mod, 'SQL_STRING_CONSTRUCTION', fn), mod);
        reference.write(combined, state); return combined;
      }
      if (assignment) {
        const converted = numeric([left, right], node, state);
        reference.write(converted, state); return converted;
      }
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
        ts.SyntaxKind.CaretToken].includes(op)) return numeric([left, right], node, state);
      const combined = union(left, right);
      return op === ts.SyntaxKind.PlusToken ? step(addition(left, right), loc(node, mod, 'SQL_STRING_CONSTRUCTION', fn), mod) : combined;
    }
    if (ts.isObjectLiteralExpression(node)) {
      const properties = new Map();
      let incomplete = false, spread = unknown();
      for (const p of node.properties) {
        if (ts.isPropertyAssignment(p) && !ts.isComputedPropertyName(p.name)) properties.set(p.name.getText().replace(/^['"]|['"]$/g, ''), expr(p.initializer, state));
        else if (ts.isShorthandPropertyAssignment(p)) properties.set(p.name.text, expr(p.name, state));
        else if (ts.isPropertyAssignment(p) && ts.isComputedPropertyName(p.name) && node.properties.length === 1) {
          expr(p.name.expression, state);
          properties.set(Symbol('computed-data'), expr(p.initializer, state)); incomplete = true;
        } else {
          note(mod, 'OBJECT_MEMBER_UNRESOLVED'); incomplete = true;
          if (ts.isSpreadAssignment(p)) spread = union(spread, expr(p.expression, state));
        }
      }
      return value('object', spread.trace, { unknown: incomplete, ref: { properties, unknown: incomplete,
        computedKeyOnly: node.properties.length===1 && ts.isPropertyAssignment(node.properties[0]) && ts.isComputedPropertyName(node.properties[0].name),
        trace: union(spread, ...properties.values()).trace,...(state.nodeMode?{nodeIdentity:{}}:{}) } });
    }
    if (ts.isArrayLiteralExpression(node)) return {...union(...node.elements.map(e => {const v=expr(e,state);return v.tag==='exposureResponse'?constant(null):v;})), responseLocations:undefined, environmentResponses:undefined};
    if (ts.isNewExpression(node) || ts.isCallExpression(node)) {
      const callee = unwrap(node.expression);
      const receiverInput = ts.isPropertyAccessExpression(callee) ? expr(callee.expression, state) : undefined;
      const callable = receiverInput ? undefined : expr(callee, state);
      const global = ts.isIdentifier(callee) && !state.vars.has(callee.text) && !mod.imports.has(callee.text) && !mod.declared.has(callee.text);
      const args = (node.arguments ?? []).map(a => expr(a, state));
      const regexResult=regexSupport.call(node,callee,receiverInput,args,state);
      if(regexResult)return regexResult;
      const globalObject = name => ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression) && callee.expression.text === name
        && !state.vars.has(name) && !mod.imports.has(name) && !mod.declared.has(name);
      if(state.nodeMode) {
        const member=ts.isPropertyAccessExpression(callee)?property(receiverInput,callee.name.text,callee,state):callable;
        const supported=nodeSupport.call(node,callee,receiverInput,args,state,global,member);
        if(supported)return supported.value;
        if(member?.target&&!member.unknown&&!member.ref?.unknown) {
          if(ts.isNewExpression(node))return nodeSupport.construct(member.target,args,state);
          const passed=args.map(a=>step(a,loc(node,mod,'FUNCTION_ARGUMENT',fn),mod));
          const returned=invoke(member.target,passed,state.depth+1,state.context,state.stack,state.uncertain,state.exposureUncertain,receiverInput);
          if(member.effects?.length)invalidateWrites(member.effects,state,union(...args));
          if(returned.tag==='express-router'&&!returned.unknown&&!returned.ref?.unknown)
            append(result.nodeUses,{ruleId:'JS_SERVER_ENTRY_CONTEXT',kind:'CALL_LINKED',operation:'STATIC_ROUTER_FACTORY_RETURN',
              location:loc(node,mod,'ROUTER_FACTORY_CALL',fn),trace:[loc(member.target.node,member.target.mod,'ROUTER_FACTORY_TARGET',member.target)],
              limitations:['STATIC_CALL_ONLY_NOT_RUNTIME_PROOF']},mod);
          return step(returned,loc(node,mod,'FUNCTION_RETURN',fn),mod);
        }
      }
      if (globalObject('console') && ['log','info','warn','error','debug'].includes(callee.name.text)) {
        const logged=union(...args);
        observeExposure(mod.syntaxIndex.writes.has('console')||mod.syntaxIndex.aliases.has('console')||mod.consoleMutated?{...logged,unknown:true}:logged, node, state, 'LOG_ARGUMENT'); return constant(undefined);
      }
      if (globalObject('JSON') && callee.name.text === 'stringify') {
        if(args[0]?.tag==='exposureResponse')return {...unknown(),exposures:exposureSources(args[0])};
        const body=responseBody(args[0]);
        return { tag:'serialized', trace:[], exposures:body.origins, exposureTrail:body.trail, unknown:body.unresolved || args.length>1 };
      }
      const nextResponse=ts.isPropertyAccessExpression(callee)&&ts.isIdentifier(callee.expression)
        &&mod.nextResponses?.has(callee.expression.text)&&!state.vars.has(callee.expression.text)&&callee.name.text==='json';
      if (global && callee.text === 'Response' && ts.isNewExpression(node) || globalObject('Response') && callee.name.text === 'json' || nextResponse) {
        const body=responseBody(args[0]), location=loc(node,mod,'HTTP_RESPONSE',fn);
        if(ts.isNewExpression(node) && args[0]?.ref)body.unresolved=true;
        return { tag:'exposureResponse', trace:[], exposures:body.origins, exposureTrail:body.trail,
          unknown:body.unresolved || state.uncertain || state.exposureUncertain, responseLocations:[location],
          environmentResponses:[{...body, location}] };
      }
      if (ts.isPropertyAccessExpression(callee) && callee.name.text==='get'
          && ts.isPropertyAccessExpression(callee.expression) && callee.expression.name.text==='env'
          && ts.isIdentifier(callee.expression.expression) && callee.expression.expression.text==='Deno'
          && mod.denoGlobals && !state.vars.has('Deno') && args.length===1) {
        const name=args[0];
        const publicValue=hasConstant(name) && (['SUPABASE_ANON_KEY','SUPABASE_PUBLISHABLE_KEY','SUPABASE_URL'].includes(name.constant) || /^PUBLIC_[A-Z0-9_]+$/.test(name.constant));
        const secret=hasConstant(name) && /(?:SECRET|SERVICE_ROLE|PRIVATE_KEY|PASSWORD|API_KEY|ACCESS_TOKEN|REFRESH_TOKEN)/i.test(String(name.constant)) && !publicValue;
        const selected=name.trace.some(s=>['QUERY_PARAMETER','REQUEST_BODY','REQUEST_HEADER','ROUTE_PARAMETER','REQUEST_URL'].includes(s.kind)) && !name.unknown;
        const origin=loc(node,mod,selected?'REQUEST_SELECTED_ENVIRONMENT_VALUE':secret?'SERVER_SECRET_ENVIRONMENT_VALUE':publicValue?'DECLARED_PUBLIC_ENVIRONMENT_VALUE':'ENVIRONMENT_VALUE_UNVERIFIED',fn);
        return value('environmentValue',[],{unknown:!!name.unknown, exposures:[...(selected?name.trace:[]),origin]});
      }
      if (ts.isIdentifier(callee)) {
        const target = !state.nodeMode || !callable?.unknown&&!callable?.ref?.unknown ? callable?.target : undefined;
        if (target && ts.isCallExpression(node)) {
          const passed = args.map(a => step(a, loc(node, mod, 'FUNCTION_ARGUMENT', fn), mod));
          return invoke(target, passed, state.depth + 1, state.context, state.stack, state.uncertain, state.exposureUncertain);
        }
        if (global) {
          if(callee.text==='Error' && ts.isNewExpression(node))return value('error-object',[],{exposures:exposureSources(args[0]),exposureTrail:exposureTrails(args[0]),unknown:exposureUncertain(args[0]??constant('')),ref:{properties:new Map(),unknown:false,trace:[]}});
          if (callee.text === 'URL' && ts.isNewExpression(node)) {
            const input = args[0] ?? unknown(), base = args[1];
            const combined = base ? union(input, base) : input;
            return value('url', combined.trace, { unknown: input.unknown || base?.unknown,
              ref: { http: constructedUrl(input, base), identity: {}, properties: new Map(), trace: combined.trace, checks: {}, unknown: false } });
          }
          if (callee.text === 'Request' && ts.isNewExpression(node)) {
            const input = args[0] ?? unknown();
            return value('outboundRequest', input.trace, { unknown: input.unknown,
              ref: { http: destinationOf(input), properties: new Map(), trace: input.trace, unknown: false } });
          }
          if (callee.text === 'fetch' && ts.isCallExpression(node)) {
            observeHttp(args[0] ?? unknown(), node, state);
            return unknown();
          }
          if (callee.text === 'encodeURIComponent' && ts.isCallExpression(node))
            return { ...(args[0] ?? unknown()), ref: undefined, destination: unresolvedDestination(), urlPrefix: undefined };
          if (callee.text === 'URLSearchParams') return value('query', args[0]?.trace ?? [], { unknown: args[0]?.unknown,
            ref: {properties: new Map(), trace: args[0]?.trace ?? [], unknown: false} });
          if (ts.isCallExpression(node) && ['Number', 'parseInt', 'parseFloat'].includes(callee.text)) {
            return numeric(args, node, state);
          }
        }
      }
      if (ts.isPropertyAccessExpression(callee)) {
        const receiver = receiverInput, method = callee.name.text;
        if (receiver.tag === 'url' && receiver.ref?.http && ['toString', 'toJSON'].includes(method))
          return value('urlText', receiver.trace, { unknown: receiver.unknown || receiver.ref.unknown, destination: destinationOf(receiver) });
        if (receiver.tag === 'query' && ['set', 'append', 'delete', 'sort'].includes(method)) {
          note(mod, 'URL_QUERY_WRITE');
          if (receiver.ref) {
            receiver.ref.queryTrace = union({trace: receiver.ref.queryTrace ?? []}, ...args).trace;
            receiver.ref.queryPartial = true;
          }
          return constant(undefined);
        }
        if (receiver.tag === 'headers' && ['set', 'append', 'delete'].includes(method)) {
          state.context.headersMutated = true; note(mod, 'HEADER_MUTATION_PARTIAL'); return constant(undefined);
        }
        if (receiver.tag === 'headers' && method === 'get') return value('input', [loc(node, mod, 'REQUEST_HEADER', fn)], { unknown: receiver.unknown || state.context.headersMutated, inputShape: 'STRING',
          exposures: hasConstant(args[0] ?? unknown()) && /^(authorization|cookie)$/i.test(args[0].constant) ? [loc(node, mod, 'AUTHENTICATION_HEADER', fn)] : [] });
        if (method === 'includes' && args[0]?.urlMember && ts.isArrayLiteralExpression(unwrap(callee.expression))
            && unwrap(callee.expression).elements.every(e => ts.isStringLiteral(e))) return value('boolean');
        if (receiver.tag === 'request' && ['json', 'text', 'formData'].includes(method)) return value('input', [loc(node, mod, 'REQUEST_BODY', fn)], { unknown: receiver.unknown, inputShape: method === 'text' ? 'STRING' : undefined });
        if (receiver.tag === 'query' && ['get', 'getAll'].includes(method)) return value('input', receiver.trace.length || receiver.ref?.queryTrace?.length ? [loc(node, mod, 'QUERY_PARAMETER', fn)] : [], { unknown: receiver.unknown || receiver.ref?.unknown || receiver.ref?.queryPartial, inputShape: method === 'get' ? 'STRING' : 'ARRAY' });
        if (receiver.tag === 'input' && method === 'get') return receiver;
        if (receiver.tag === 'database' && method === 'prepare') {
          const sql = { ...(args[0] ?? unknown()) };
          // A partial control path does not erase a directly observed literal/bound query.
          // Unknown value writes are tracked separately in the variable/heap state.
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
      for (const callback of [callable, ...args]) if (callback?.effects?.length) {
        invalidateWrites(callback.effects, state, incoming); note(mod, 'CLOSURE_SIDE_EFFECTS_UNRESOLVED');
      }
      for (const argument of [...args, ...(receiverInput ? [receiverInput] : [])]) if (argument.ref) {
        if(state.nodeMode){invalidateNodeReference(argument.ref,state,incoming);continue;}
        argument.ref.unknown = true; argument.ref.trace = union(argument, incoming).trace;
        argument.ref.properties.clear();
      }
      note(mod, 'CALL_TARGET_UNRESOLVED');
      return { ...incoming, unknown: true, environmentResponses:undefined, destination: unresolvedDestination(), urlPrefix: undefined };
    }
    if (ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)) {
      const operand = expr(node.operand, state);
      if (node.operator === ts.SyntaxKind.ExclamationToken)
        return truth(operand) !== undefined ? constant(!truth(operand))
          : value('boolean', [], { predicateInput: operand.predicateInput ?? (operand.unknown ? operand : undefined) });
      if (hasConstant(operand)) {
        if (node.operator === ts.SyntaxKind.PlusToken) return constant(+operand.constant);
        if (node.operator === ts.SyntaxKind.MinusToken) return constant(-operand.constant);
        if (node.operator === ts.SyntaxKind.TildeToken) return constant(~operand.constant);
      }
      const converted = numeric([operand], node, state);
      if ([ts.SyntaxKind.PlusPlusToken, ts.SyntaxKind.MinusMinusToken].includes(node.operator) && ts.isIdentifier(node.operand)) state.vars.set(node.operand.text, converted);
      return converted;
    }
    if (node.kind === ts.SyntaxKind.TrueKeyword) return constant(true);
    if (node.kind === ts.SyntaxKind.FalseKeyword) return constant(false);
    if (node.kind === ts.SyntaxKind.NullKeyword) return constant(null);
    if (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) return state.nodeMode?nodeSupport.functionValue(node,state,node.parent?.name?.text??'handler'):unsupportedClosure(node, state);
    note(mod, 'EXPRESSION_UNSUPPORTED'); invalidateWrites(writtenNames(node, state), state); state.uncertain = true; return unknown();
  }
  // Scalars are immutable snapshots. A branch gets a separate heap, preserving aliases inside it.
  function fork(state) {
    const refs = new Map();
    const clone = v => {
      if (!v.ref) return v;
      if (!refs.has(v.ref)) {
        const copy = { ...v.ref, properties: new Map() }; refs.set(v.ref, copy);
        if(v.ref.originParent)copy.originParent=clone({ref:v.ref.originParent}).ref;
        for (const [key, property] of v.ref.properties) { tick(state.mod); copy.properties.set(key, clone(property)); }
      }
      return { ...v, ref: refs.get(v.ref) };
    };
    return { ...state, vars: new Map([...state.vars].map(([name, v]) => [name, clone(v)])),
      thisValue:state.nodeMode&&state.thisValue?clone(state.thisValue):state.thisValue,forkRefs: refs };
  }
  function mergeVars(state, branches) {
    const merged = new Map(), urlRefs = new Map();
    for (const key of new Set(branches.flatMap(b => [...b.vars.keys()]))) {
      tick(state.mod);
      const alternatives = branches.map(b => b.vars.get(key) ?? unknown());
      if (alternatives.some(v => v.ref) && !alternatives.every(v => v.ref === alternatives[0].ref
          || v.ref?.identity && v.ref.identity === alternatives[0].ref?.identity)) note(state.mod, 'OBJECT_BRANCH_MERGE_PARTIAL');
      const joined = union(...alternatives);
      if (joined.ref?.identity) {
        if (urlRefs.has(joined.ref.identity)) joined.ref = urlRefs.get(joined.ref.identity);
        else urlRefs.set(joined.ref.identity, joined.ref);
      }
      merged.set(key, joined);
    }
    state.vars = merged;
    state.uncertain = state.uncertain || branches.some(b => b.uncertain);
    state.exposureUncertain = state.exposureUncertain || branches.some(b => b.exposureUncertain);
  }
  function guardBranches(node, condition, yes, no) {
    yes.exposureUncertain = no.exposureUncertain = true;
    const predicate = condition.predicateInput ?? condition;
    if(yes.nodeMode&&predicate.unknown&&predicate.trace.length)yes.uncertain=no.uncertain=true;
    if (predicate.unknown && predicate.trace.length) for (const branch of [yes, no]) {
      for (const [name, v] of branch.vars) if (v.trace.some(t => predicate.trace.some(c => JSON.stringify(c) === JSON.stringify(t))))
        branch.vars.set(name, { ...v, unknown: true });
    }
    refineAllowlist(node, true, yes); refineAllowlist(node, false, no);
    regexSupport.refine(node,true,yes);regexSupport.refine(node,false,no);
    refineUrlAllowlist(node, true, yes); refineUrlAllowlist(node, false, no);
  }
  function refineUrlAllowlist(original, accepted, state, depth = 0) {
    if (depth > 3) return;
    const node = unwrap(original);
    if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.ExclamationToken)
      return refineUrlAllowlist(node.operand, !accepted, state, depth + 1);
    if (ts.isBinaryExpression(node)) {
      const op = node.operatorToken.kind;
      if (op === ts.SyntaxKind.AmpersandAmpersandToken && accepted || op === ts.SyntaxKind.BarBarToken && !accepted) {
        refineUrlAllowlist(node.left, accepted, state, depth + 1);
        refineUrlAllowlist(node.right, accepted, state, depth + 1); return;
      }
      if ([ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken].includes(op)
          && accepted === (op === ts.SyntaxKind.EqualsEqualsEqualsToken)) {
        const left = unwrap(node.left), right = unwrap(node.right);
        if (ts.isStringLiteral(right)) mark(left, [right.text]);
        else if (ts.isStringLiteral(left)) mark(right, [left.text]);
      }
    } else if (accepted && ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)
        && node.expression.name.text === 'includes' && node.arguments.length === 1) {
      const list = unwrap(node.expression.expression);
      if (ts.isArrayLiteralExpression(list) && list.elements.length > 0 && list.elements.length <= 30
          && list.elements.every(e => ts.isStringLiteral(e))) mark(unwrap(node.arguments[0]), list.elements.map(e => e.text));
    }
    function mark(member, literals) {
      if (!ts.isPropertyAccessExpression(member) || !ts.isIdentifier(member.expression)) return;
      const v = state.vars.get(member.expression.text), key = member.name.text;
      if (!v?.ref?.http || v.tag !== 'url' || v.ref.unknown) return;
      if (!(key === 'protocol' && literals.every(t => ['http:', 'https:'].includes(t))
          || key === 'hostname' && literals.every(t => /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(t)))) return;
      v.ref.checks = { ...v.ref.checks, [key]: loc(original, state.mod, 'PARSED_URL_ALLOWLIST', state.fn) };
    }
  }
  function observeHttp(input, node, state) {
    const {mod, fn} = state;
    let destination = destinationOf(input);
    if (state.uncertain || input.traceTruncated) destination = unresolvedDestination();
    const defenses = Object.values(input.ref?.checks ?? {});
    const limits = ['REDIRECT_DNS_REACHABILITY_NOT_VERIFIED', 'PATH_FEASIBILITY_NOT_VERIFIED'];
    if (destination.kind === 'ALLOWLISTED_DESTINATION') limits.push('PORT_POLICY_NOT_VERIFIED');
    if (destination.kind === 'UNRESOLVED_DESTINATION') { limits.push('DESTINATION_FLOW_UNRESOLVED'); note(mod, 'DESTINATION_FLOW_UNRESOLVED'); }
    const trace = union(input, {trace: input.ref?.trace ?? []}).trace.map(l => l.kind === 'SQL_STRING_CONSTRUCTION' ? {...l, kind: 'URL_STRING_CONSTRUCTION'} : l);
    const usage = { ...destination, location: loc(node, mod, 'HTTP_REQUEST_CALL', fn), trace,
      defenses, limitations: limits };
    append(result.httpUses, usage, mod);
    state.context.resources.push(usage.location);
    if (trace.length && ['INPUT_IN_DESTINATION', 'UNRESOLVED_DESTINATION'].includes(usage.kind)) {
      append(result.findings, { ruleId: 'TS_SSRF_INPUT_FLOW', kind: 'INPUT_TO_HTTP_DESTINATION',
        confidence: usage.kind === 'INPUT_IN_DESTINATION' ? 'HIGH' : 'MEDIUM', disposition: 'REVIEW_REQUIRED',
        source: trace[0], sink: usage.location, flow: trace, defenses, limitations: limits,
        message: '사용자 입력이 서버의 요청 주소에 전달됩니다. 실제 목적지 제어 여부와 허용 목록을 확인하세요.',
        recommendation: 'URL을 파싱하고 프로토콜·호스트를 서버의 정확한 허용 목록으로 제한하세요. 리다이렉트와 DNS·네트워크 제한은 별도로 검증하세요.' }, mod);
    }
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
      } else if ((ts.isFunctionDeclaration(s) || ts.isClassDeclaration(s)) && s.name) locals.add(s.name.text);
      for (const name of locals) state.vars.set(name, { ...unknown(), uninitialized: true });
      for (const s of node.statements) if (ts.isFunctionDeclaration(s) && s.name) state.vars.set(s.name.text, state.nodeMode?nodeSupport.functionValue(s,state,s.name.text):unsupportedClosure(s, state));
      const restore = () => { for (const name of locals) { if (prior.has(name)) state.vars.set(name, prior.get(name)); else state.vars.delete(name); } };
      const returns = [];
      for (const s of node.statements) { const r = statement(s, state); returns.push(...r.values); if (r.stops) { restore(); return { values: returns, stops: true }; } }
      restore();
      return { values: returns, stops: false };
    }
    if (ts.isVariableStatement(node)) for (const d of node.declarationList.declarations) {
      if (!d.initializer && !(node.declarationList.flags & ts.NodeFlags.BlockScoped) && ts.isIdentifier(d.name) && state.vars.has(d.name.text)) continue;
      const v = d.initializer ? expr(d.initializer, state) : constant(undefined);
      bind(d.name, step(v, loc(d, mod, 'VARIABLE', fn), mod), state);
    }
    else if (ts.isExpressionStatement(node)) expr(node.expression, state);
    else if (ts.isReturnStatement(node)) {
      let returned=expr(node.expression,state);
      if(state.fn.nextServerReturn) {
        const body=responseBody(returned),location=loc(node,state.mod,'SERVER_FUNCTION_RETURN',state.fn);
        returned={...returned,environmentResponses:[{...body,unresolved:body.unresolved||state.uncertain||state.exposureUncertain,location}]};
      }
      return {values:[state.nodeMode&&state.uncertain?{...returned,unknown:true}:returned],stops:true};
    }
    else if (ts.isThrowStatement(node)) { expr(node.expression, state); return { values: [], stops: true }; }
    else if (ts.isIfStatement(node)) {
      const condition = expr(node.expression, state);
      if (truth(condition) === true) return statement(node.thenStatement, state);
      if (truth(condition) === false) return node.elseStatement ? statement(node.elseStatement, state) : { values: [], stops: false };
      state.context.checks.push(loc(node.expression, mod, 'CONDITIONAL_CHECK', fn));
      const a = fork(state), b = fork(state);
      if(state.nodeMode&&state.context.setup)a.uncertain=b.uncertain=true;
      if(state.nodeMode&&state.context.setup)a.uncertain=b.uncertain=true;
      // A validator we cannot model may restrict this input; do not promote it as an unguarded path.
      guardBranches(node.expression, condition, a, b);
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
      else if (node.initializer) expr(node.initializer, branch);
      if (node.condition) expr(node.condition, branch);
      if (node.expression) expr(node.expression, branch);
      const r = statement(node.statement, branch);
      if (node.incrementor) expr(node.incrementor, branch);
      mergeVars(state, [state, branch]); return { ...r, stops: false };
    } else if (ts.isTryStatement(node)) {
      const thrown=node.tryBlock.statements.length===1 && ts.isThrowStatement(node.tryBlock.statements[0]) ? unwrap(node.tryBlock.statements[0].expression) : undefined;
      const known=thrown && ts.isNewExpression(thrown) && ts.isIdentifier(thrown.expression) && thrown.expression.text==='Error'
        && !state.vars.has('Error') && !mod.imports.has('Error') && !mod.declared.has('Error')
        && (thrown.arguments??[]).every(a=>ts.isStringLiteral(a)) && !node.finallyBlock;
      if(known && node.catchClause && node.catchClause.block.statements.length && ts.isReturnStatement(node.catchClause.block.statements.at(-1))){
        const branch=fork(state);const name=node.catchClause.variableDeclaration?.name;const error=expr(thrown,branch);
        if(name && ts.isIdentifier(name))branch.vars.set(name.text,error);
        const handled=statement(node.catchClause.block,branch);mergeVars(state,[branch]);return handled;
      }
      note(mod, 'EXCEPTION_FLOW_PARTIAL');
      const a = { ...fork(state), uncertain: true }, b = { ...fork(state), uncertain: true }, ar = statement(node.tryBlock, a);
      const catchName=node.catchClause?.variableDeclaration?.name;
      if(catchName && ts.isIdentifier(catchName))b.vars.set(catchName.text,value('caught-error',[],{unknown:true}));
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
    } else if (![ts.SyntaxKind.EmptyStatement, ts.SyntaxKind.BreakStatement, ts.SyntaxKind.FunctionDeclaration].includes(node.kind)) {
      note(mod, 'STATEMENT_UNSUPPORTED'); invalidateWrites(writtenNames(node, state), state); state.uncertain = true;
    }
    return { values: [], stops: false };
  }
  const canonicalFunctions = new WeakMap();
  function serverEnvironmentValue(node,state) {
    const {mod,fn}=state;
    const index=mod.syntaxIndex;
    const nodeEnvironment=state.nodeMode&&!index.bindings.has('process')&&!index.writes.has('process')
      &&!index.aliases.has('process')&&!mod.processEscaped;
    if (!(ts.isPropertyAccessExpression(node)||ts.isElementAccessExpression(node)) || !ts.isPropertyAccessExpression(node.expression)
        || !ts.isIdentifier(node.expression.expression) || node.expression.expression.text!=='process' || node.expression.name.text!=='env')return;
    if(!(mod.nextContract&&mod.nextEnvironment||nodeEnvironment)||state.vars.has('process')){
      if(state.nodeMode||mod.nextContract)note(mod,'SERVER_ENVIRONMENT_PROVENANCE_UNVERIFIED');return;
    }
    const key=ts.isPropertyAccessExpression(node)?constant(node.name.text):expr(node.argumentExpression,state);
    const publicValue=hasConstant(key)&&(mod.nextContract&&/^NEXT_PUBLIC_[A-Z0-9_]+$/.test(String(key.constant))
      ||['SUPABASE_ANON_KEY','SUPABASE_PUBLISHABLE_KEY','SUPABASE_URL'].includes(key.constant));
    const publicHint=nodeEnvironment&&hasConstant(key)&&/^(?:NEXT_PUBLIC_|VITE_)/.test(String(key.constant));
    const secret=hasConstant(key)&&!publicValue&&!publicHint&&/(?:SECRET|PRIVATE_KEY|PASSWORD|API_KEY|ACCESS_TOKEN|REFRESH_TOKEN|SERVICE_ROLE|DATABASE_URL)/i.test(String(key.constant));
    const selected=key.trace.some(s=>['QUERY_PARAMETER','REQUEST_BODY','REQUEST_HEADER','ROUTE_PARAMETER','SERVER_FUNCTION_ARGUMENT','EXPRESS_QUERY','EXPRESS_BODY','EXPRESS_PARAMS'].includes(s.kind))&&!key.unknown;
    return value('environmentValue',[],{unknown:!!key.unknown,exposures:[...(selected?key.trace:[]),loc(node,mod,selected?'REQUEST_SELECTED_ENVIRONMENT_VALUE':secret?'SERVER_SECRET_ENVIRONMENT_VALUE':publicValue?'DECLARED_PUBLIC_ENVIRONMENT_VALUE':'ENVIRONMENT_VALUE_UNVERIFIED',fn)]});
  }
  function invoke(fn, args, depth, context, stack, uncertain = false, exposureUncertain = false,thisValue,constructing=false) {
    const { mod, node } = fn;
    if (depth > limits.maxDepth || stack.has(fn)) {
      if(fn.nodeMode){
        const effectState={mod,nodeMode:true};
        for(const arg of [...args,thisValue])if(arg?.ref)invalidateNodeReference(arg.ref,effectState,unknown());
      }
      note(mod, 'CALL_DEPTH_EXCEEDED'); return { ...union(...args), unknown: true };
    }
    tick(mod); mod.visited.add(canonicalFunctions.get(fn) ?? fn); mod.record.functionsAnalyzed = mod.visited.size;
    const state = { mod, fn, vars: new Map(fn.closure??[]), depth, context, uncertain, exposureUncertain,
      nodeMode:!!fn.nodeMode,nodeMutations:new Set(),thisValue:fn.lexicalThis??thisValue,constructing,stack: new Set([...stack, fn]) };
    const names = (binding, callback) => {
      if (ts.isIdentifier(binding)) callback(binding.text);
      else if (ts.isObjectBindingPattern(binding) || ts.isArrayBindingPattern(binding))
        binding.elements.forEach(e => { if (e.name) names(e.name, callback); });
    };
    // Hoist var bindings without executing initializers or descending into other functions.
    const hoist = n => {
      tick(mod);
      if (n !== node && ts.isFunctionLike(n)) return;
      if (ts.isVariableDeclarationList(n) && !(n.flags & ts.NodeFlags.BlockScoped))
        n.declarations.forEach(d => names(d.name, name => state.vars.set(name, constant(undefined))));
      ts.forEachChild(n, hoist);
    };
    if (node.body) hoist(node.body);
    node.parameters.forEach(p => names(p.name, name => state.vars.set(name, { ...unknown(), uninitialized: true })));
    node.parameters.forEach((p, i) => {
      if (p.dotDotDotToken) note(mod, 'REST_PARAMETER_UNSUPPORTED');
      bind(p.name, p.dotDotDotToken ? { ...union(...args.slice(i)), unknown: true }
        : defaultValue(args[i] ?? constant(undefined), p.initializer, state), state);
    });
    if (!node.body) return unknown();
    if (!ts.isBlock(node.body)&&!state.nodeMode) return expr(node.body, state);
    const r = ts.isBlock(node.body)?statement(node.body,state):{values:[expr(node.body,state)],stops:true};
    // Branch-local heap copies cannot prove a mutation-free return to the caller.
    if(state.nodeMode){
      // Only effects on this call's reachable identities invalidate caller aliases.
      // File-wide coverage notes must not act as mutable heap state.
      const seen=new Set();
      const apply=v=>{
        if(!v?.ref||seen.has(v.ref))return;tick(mod);seen.add(v.ref);
        if(v.ref.nodeIdentity&&state.nodeMutations.has(v.ref.nodeIdentity))invalidateNodeReference(v.ref,state,unknown());
        else for(const child of v.ref.properties.values())apply(child);
      };
      for(const arg of [...args,thisValue])apply(arg);
    }else if (['PROPERTY_WRITE_UNRESOLVED', 'CLOSURE_SIDE_EFFECTS_UNRESOLVED', 'URL_PROPERTY_WRITE', 'URL_QUERY_WRITE']
        .some(reason => mod.record.limitations.has(reason))) {
      for (const arg of args) if (arg.ref) {
        arg.ref.unknown = true; arg.ref.trace = union({ trace: arg.ref.trace }, ...args).trace; arg.ref.properties.clear();
        note(mod, 'CALLER_HEAP_EFFECTS_PARTIAL');
      }
    }
    const returns=[...r.values,...(!r.stops?[constant(undefined)]:[])];
    const combined=union(...returns);
    const withResponses={...combined,environmentResponses:returns.flatMap(v=>v.environmentResponses??[]).slice(0,20)};
    return state.nodeMode&&returns.length>1&&returns.length<=4?{...withResponses,nodeAlternatives:returns}:withResponses;
  }
  // Reserve bounded declaration passes before flow tracing consumes the remainder.
  // Its ticks still count against the same global cap; no target code is run.
  let precomputedPolicies;
  phase='POLICY';
  if(input.policyFiles?.length) {
    let sqlWork=0;const sqlCap=Math.floor(limits.maxSteps*(modules.size?0.25:0.9));
    const globalTick=()=>charged();
    try {precomputedPolicies=analyzePolicies(input.policyFiles,globalTick,()=>{
      if(++sqlWork>sqlCap)throw Error('POLICY_STEP_BUDGET');globalTick();
    });}catch {/* The ordinary unavailable path below stays fail-closed. */}
  }
  phase='CLIENT';
  let clientWork=0;const clientCap=Math.floor(limits.maxSteps*0.15);
  let writePass;
  const precomputedSupabase=supabaseAnalysis({ts,modules,input,sourceImports,precomputedPolicies,prepareWritePass:pass=>{writePass=pass;},tick:()=>{
    if(clientWork>=clientCap)throw Error('CLIENT_STEP_BUDGET');clientWork++;
    charged();
  }});
  phase='ENTRY_DISCOVERY';
  denoEntries({ts,modules,resolve,claimFunction,tick,note,input});
  nextEntries({ts,modules,input,tick,note});
  let requestEvidenceBytes=Buffer.byteLength(JSON.stringify(precomputedSupabase));
  for(const access of precomputedSupabase.accesses){
    const evidence=access.authorizationEvidence,at=evidence?.enclosingFunction,mod=at&&modules.get(at.filePath);
    if(!mod)continue;
    try {
      tick(mod);
      const entries=mod.entries.filter(e=>['NEXT_ROUTE_HANDLER','NEXT_SERVER_FUNCTION'].includes(e.kind)&&(()=>{
        const p=loc(e.fn.node,mod,e.kind,e.fn);return p.line===at.line&&p.column===at.column;
      })());
      if(entries.length!==1)continue;
      const entry=loc(entries[0].fn.node,mod,entries[0].kind,entries[0].fn),size=Buffer.byteLength(JSON.stringify(entry))+30;
      if(requestEvidenceBytes+size>275000){note(mod,'CLIENT_POLICY_EVIDENCE_OUTPUT_LIMIT');break;}
      evidence.requestEntry=entry;requestEvidenceBytes+=size;
    }catch{note(mod,'NEXT_ACCESS_ASSOCIATION_BUDGET_LIMIT');break;}
  }
  phase='CLIENT';
  writePass?.();
  phase='ENTRY_DISCOVERY';
  entryContracts({ts,modules,tick,note,loc,append,result});
  nodeSupport=nodeServer({ts,modules,limits,result,input,tick,note,value,unknown,constant,loc,append,union,expr,invoke,statement,writtenNames,claimFunction,observeExpressResponse});
  nodeSupport.discover();
  phase='FLOW';
  for (const mod of modules.values()) for (const entry of mod.entries) {
    const context = { entry: loc(entry.registrationNode ?? entry.fn.node, mod, entry.kind, entry.fn), checks: [], defenses: [], resources: [] };
    try {
      // Runtime require() must use this same graph as captured module values.
      const isolate = entryState(() => tick(mod), canonicalFunctions);
      Object.defineProperty(context, 'isolate', {value: isolate});
      const entryFn = entry.fn.nodeMode ? isolate(entry.fn) : entry.fn;
      if(entry.fn.nodeMode)note(mod,'MULTI_REQUEST_GLOBAL_LIFECYCLE_NOT_VERIFIED');
      if(entry.registration){context.checks.push(entry.registration);note(mod,'EXPRESS_MIDDLEWARE_AND_RUNTIME_NOT_VERIFIED');}
      const returned = invoke(entryFn, entry.kind === 'NEXT_ROUTE_HANDLER' ? [value('request'),value('nextContext',[],{paramNames:entry.paramNames})]
        : entry.kind==='NEXT_SERVER_FUNCTION'?entry.fn.node.parameters.map(p=>value('input',[loc(p,mod,'SERVER_FUNCTION_ARGUMENT',entry.fn)]))
        : entry.kind === 'WORKER_FETCH' || entry.kind === 'DENO_HTTP_HANDLER' ? [value('request'), value('env')] : entry.kind==='EXPRESS_HANDLER'
        ?[value('express-request'),value('express-response'),unknown()]:[value('context')], 0, context, new Set(),!!entry.uncertain);
      if (returned.responseLocations?.length) observeExposure(returned, entry.fn.node, { mod, fn: entry.fn, uncertain: false }, 'HTTP_RESPONSE_RETURN');
      observeEnvironmentResponses(returned,{mod,fn:entry.fn});
    } catch { note(mod, 'ANALYSIS_BUDGET_EXCEEDED'); }
    for (const field of ['checks', 'defenses', 'resources']) {
      context[field] = context[field].filter((item, i, all) => all.findIndex(other => JSON.stringify(item) === JSON.stringify(other)) === i);
      if (context[field].length > 100) { context[field] = context[field].slice(0, 100); note(mod, 'CONTEXT_DETAILS_LIMIT_EXCEEDED'); }
    }
    const { headersMutated: ignoredHeaderState, ...publicContext } = context;
    append(result.authorizationContexts, { ...publicContext, conclusion: 'NOT_VERIFIED', limitations: [
      '조건 분기만으로 인증·소유권 검증을 입증하지 않습니다.',
      '전역 미들웨어·세션 검증·리소스 소유권과 실패 시 차단 경로를 직접 확인하세요.'
    ] }, mod);
  }
  for (const mod of modules.values()) {
    mod.record.tracedPrepareCallSites = new Set(result.sqlUses.filter(s => s.location.filePath === mod.filePath)
      .map(s => `${s.location.line}:${s.location.column}`)).size;
    if (mod.record.prepareCallSites > mod.record.tracedPrepareCallSites) note(mod, 'PREPARE_CALLS_OUTSIDE_TRACED_FLOW');
    mod.record.tracedHttpCallSites = new Set(result.httpUses.filter(s => s.location.filePath === mod.filePath)
      .map(s => `${s.location.line}:${s.location.column}`)).size;
    if (mod.record.httpCallSites > mod.record.tracedHttpCallSites) note(mod, 'HTTP_CALLS_OUTSIDE_TRACED_FLOW');
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
  result.supabaseAnalysis=precomputedSupabase;
  result.supabaseAnalysis.budgetUsage={AST_NODES_INDEXED:astNodes,STEPS_LIMIT:limits.maxSteps,STEPS_USED:steps,
    STEPS_SETUP:phaseSteps.SETUP??0,STEPS_POLICY:phaseSteps.POLICY??0,STEPS_CLIENT:phaseSteps.CLIENT??0,
    STEPS_ENTRY_DISCOVERY:phaseSteps.ENTRY_DISCOVERY??0,STEPS_FLOW:phaseSteps.FLOW??0,
    CLIENT_WORK_LIMIT:clientCap,POLICY_WORK_LIMIT:Math.floor(limits.maxSteps*(modules.size?0.25:0.9))};
  return result;
}
