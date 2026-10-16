import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze } from '../analyzer.mjs';

const worker = body => `export default { async fetch(request: Request, env: Env) { ${body} } };`;
const run = (content, extra = [], limits) => analyze({ files: [{ filePath: 'worker/index.ts', content }, ...extra] }, limits);
const source = 'const input = new URL(request.url).searchParams.get("id");';

test('A: query input reaches D1 SQL, without storing source literals', () => {
  const r = run(worker(`${source} return env.DB.prepare("SELECT * FROM items WHERE id=" + input).all();`));
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0].confidence, 'HIGH');
  assert.equal(r.findings[0].source.kind, 'QUERY_PARAMETER');
  assert.equal(r.sqlUses[0].executionObserved, true);
  assert.ok(!JSON.stringify(r).includes('SELECT *'));
});
test('B: static prepared statement binds external values, not SQL', () => {
  const r = run(worker(`${source} return env.DB.prepare("SELECT * FROM items WHERE id=?").bind(input).first();`));
  assert.equal(r.findings.length, 0);
  assert.equal(r.sqlUses[0].kind, 'PARAMETERIZED_QUERY');
  assert.equal(r.sqlUses[0].defenses[0].kind, 'VALUE_BINDING');
});
test('binding after interpolating SQL does not remove the dangerous query path', () => {
  const r = run(worker(source + ' return env.DB.prepare(`SELECT * FROM items WHERE id=${input} AND other=?`).bind(3).all();'));
  assert.equal(r.findings.length, 1);
  assert.equal(r.sqlUses[0].kind, 'INPUT_IN_QUERY');
  assert.equal(r.findings[0].defenses[0].kind, 'VALUE_BINDING');
  assert.ok(r.findings[0].limitations.includes('BIND_DOES_NOT_REWRITE_QUERY'));
});
test('C: assignments and variable aliases preserve input location', () => {
  const r = run(worker(`${source} let alias = input; let sql = 'SELECT * FROM items WHERE id='; sql += alias; return env.DB.prepare(sql).run();`));
  assert.equal(r.findings.length, 1);
  assert.ok(r.findings[0].flow.some(s => s.kind === 'ASSIGNMENT'));
});
test('D: relative imports and limited function arguments/returns are followed without loading modules', () => {
  const r = run(`import { query } from './query'; ${worker(`${source} return query(env.DB, input);`)}`,
    [{ filePath: 'worker/query.ts', content: `export function query(db, id) { const sql = build(id); return db.prepare(sql).first(); }
      function build(id) { return 'SELECT * FROM items WHERE id=' + id; }` }]);
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0].sink.filePath, 'worker/query.ts');
  assert.ok(r.findings[0].flow.some(s => s.kind === 'FUNCTION_ARGUMENT'));
});
test('Pages destructured context tracks route parameters and body', () => {
  for (const expression of ['params.id', '(await request.json()).id']) {
    const r = analyze({ files: [{ filePath: 'functions/api/[id].ts', content:
      `export const onRequestPost = async ({ request, params, env }) => env.DB.prepare('SELECT * FROM t WHERE id=' + ${expression}).first();` }] });
    assert.equal(r.findings.length, 1);
  }
});
test('E/F: conditional access checks are context, neither proof of authorization nor absence of it', () => {
  for (const guarded of [true, false]) {
    const r = analyze({ files: [{ filePath: 'functions/api/item.ts', content: `export async function onRequestGet({request, env, params, data}) {
      ${guarded ? 'const user = data.user; if (!user) return new Response(null, {status:401}); if (user.id !== params.ownerId) return new Response(null, {status:403});' : ''}
      return env.DB.prepare('SELECT * FROM items WHERE owner_id=?').bind(params.ownerId).first(); }` }] });
    assert.equal(r.findings.length, 0);
    assert.equal(r.authorizationContexts[0].conclusion, 'NOT_VERIFIED');
    assert.equal(r.authorizationContexts[0].checks.filter(c => c.kind === 'CONDITIONAL_CHECK').length, guarded ? 2 : 0);
  }
});
test('G: React UI and Express are not claimed as supported server authorization', () => {
  const r = analyze({ files: [{ filePath: 'src/App.tsx', content: 'export default function App(){return <p>admin</p>}' },
    { filePath: 'server.ts', content: 'app.get("/item", (req,res) => db.prepare(req.query.id));' }] });
  assert.equal(r.findings.length, 0);
  assert.ok(r.files.every(f => f.flowStatus === 'NOT_SUPPORTED'));
  assert.equal(r.status, 'PARTIAL');
  assert.equal(r.files[1].prepareCallSites, 1);
  assert.equal(r.files[1].tracedPrepareCallSites, 0);
});
test('G: invalid syntax is not no vulnerabilities', () => {
  const r = run('export default { fetch( {');
  assert.equal(r.files[0].parseStatus, 'PARSE_FAILED');
  assert.equal(r.status, 'PARTIAL');
});
test('H: depth, file, node and step limits are explicit', () => {
  const code = `${worker(`${source} return a(env.DB, input);`)}
    function a(db,id){return b(db,id)} function b(db,id){return c(db,id)} function c(db,id){return db.prepare(id)}`;
  const depth = run(code, [], { maxDepth: 1 });
  assert.ok(depth.files[0].limitations.includes('CALL_DEPTH_EXCEEDED'));
  assert.equal(depth.status, 'PARTIAL');
  assert.equal(run(code, [], { maxFileChars: 20 }).files[0].parseStatus, 'LIMIT_EXCEEDED');
  assert.equal(run(code, [], { maxNodes: 10 }).files[0].parseStatus, 'LIMIT_EXCEEDED');
  assert.ok(run(code, [], { maxSteps: 1 }).files[0].limitations.includes('ANALYSIS_BUDGET_EXCEEDED'));
});
test('unknown sanitizer retains provenance with uncertainty, never confirmed SQL injection', () => {
  const r = run(worker(`${source} return env.DB.prepare('SELECT * FROM t WHERE id=' + escapeSql(input)).all();`));
  assert.equal(r.findings[0].confidence, 'MEDIUM');
  assert.equal(r.findings[0].disposition, 'REVIEW_REQUIRED');
  assert.ok(r.findings[0].limitations.includes('QUERY_HAS_UNRESOLVED_VALUES'));
});
test('unknown string transforms preserve provenance instead of silently treating it as safe', () => {
  const r = run(worker(`${source} const transformed = input.trim(); return env.DB.prepare('SELECT * FROM t WHERE id=' + transformed);`));
  assert.equal(r.findings[0].confidence, 'MEDIUM');
});
test('module aliases cannot masquerade as numeric sanitizers; property writes are not proven safe', () => {
  const alias = run(`const Number = customConvert; ${worker(`${source} return env.DB.prepare(Number(input));`)}`);
  assert.equal(alias.findings.length, 1);
  const mutated = run(worker(`${source} const state = {sql:'SELECT 1'}; const alias = state; alias.sql = input; return env.DB.prepare(state.sql);`));
  assert.equal(mutated.findings.length, 1);
  assert.equal(mutated.findings[0].confidence, 'MEDIUM');
});
test('numeric conversion and literal selection do not taint SQL', () => {
  for (const expression of ['Number(input)', 'parseInt(input, 10)', '+input', '!input', 'input > 0', 'input * 2', 'input === "a" ? "title" : "id"']) {
    const r = run(worker(`${source} return env.DB.prepare('SELECT * FROM t ORDER BY ' + (${expression})).all();`));
    assert.equal(r.findings.length, 0);
  }
});
test('negated literal conditions keep the correct branch', () => {
  assert.equal(run(worker(`${source} if(!true) { env.DB.prepare(input); }`)).findings.length, 0);
  assert.equal(run(worker(`${source} if(!false) { env.DB.prepare(input); }`)).findings.length, 1);
});
test('unrelated names, static request values and shadowed global conversions do not get trusted', () => {
  assert.equal(run(worker('const input = new URL("https://example.invalid/?id=2").searchParams.get("id"); return env.DB.prepare(input);')).findings.length, 0);
  const r = run(`${worker(`${source} return env.DB.prepare('SELECT * FROM t WHERE id=' + Number(input));`)} function Number(x){return x;}`);
  assert.equal(r.findings.length, 1);
});
test('unreachable statements after return are not reported', () => {
  const r = run(worker(`${source} return new Response('ok'); env.DB.prepare(input);`));
  assert.equal(r.findings.length, 0);
});
test('target imports, top-level effects and scripts are never evaluated', () => {
  const r = run(`import './does-not-exist'; throw new Error('DO_NOT_EXECUTE'); ${worker('return env.DB.prepare("SELECT 1").first();')}`);
  assert.equal(r.sqlUses.length, 1);
});
test('block scoped aliases and literal false branches do not contaminate a static outer query', () => {
  const r = run(worker(`${source} let sql = 'SELECT 1'; { const sql = input; } if(false) { env.DB.prepare(input); } return env.DB.prepare(sql).all();`));
  assert.equal(r.findings.length, 0);
  assert.equal(r.sqlUses.length, 1);
});
test('loops and callback-based flow disclose partial support', () => {
  const r = run(worker(`${source} for(const x of [input]) { env.DB.prepare(x); } [input].map(x => env.DB.prepare(x));`));
  assert.ok(r.files[0].limitations.includes('LOOP_FLOW_PARTIAL'));
  assert.ok(r.files[0].limitations.includes('CALLBACK_FLOW_UNSUPPORTED'));
  assert.equal(r.status, 'PARTIAL');
});
test('long traces retain the original source and explicitly lower completeness', () => {
  const aliases = Array.from({length:30}, (_,i) => `const v${i} = ${i ? `v${i-1}` : 'input'};`).join(' ');
  const r = run(worker(`${source} ${aliases} return env.DB.prepare(v29);`));
  assert.equal(r.findings[0].source.kind, 'QUERY_PARAMETER');
  assert.equal(r.findings[0].confidence, 'MEDIUM');
  assert.ok(r.findings[0].limitations.includes('TRACE_DETAILS_TRUNCATED'));
});
