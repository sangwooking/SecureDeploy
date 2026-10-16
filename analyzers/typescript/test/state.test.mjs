import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze } from '../analyzer.mjs';

const input = 'let id = new URL(request.url).searchParams.get("id");';
const sink = expression => `return env.DB.prepare(${expression}).all();`;
const run = (body, functions = '') => analyze({ files: [{ filePath: 'worker.ts',
  content: `${functions} export default { fetch(request,env) { ${input} ${body} } };` }] });
function expectFlow(result, expected) {
  assert.equal(result.sqlUses.length, 1);
  if (expected === 'RISK') {
    assert.equal(result.sqlUses[0].kind, 'INPUT_IN_QUERY');
    assert.equal(result.findings[0]?.confidence, 'HIGH');
  } else if (expected === 'SAFE') {
    assert.equal(result.findings.length, 0);
    assert.match(result.sqlUses[0].kind, /^(STATIC|PARAMETERIZED)_QUERY$/);
  } else {
    assert.ok(result.sqlUses[0].limitations.includes('QUERY_HAS_UNRESOLVED_VALUES'));
    assert.ok(result.findings.every(f => f.confidence !== 'HIGH'));
    assert.equal(result.status, 'PARTIAL');
  }
}

const pairs = [
  ['left value captured before assignment', sink('id + (id = "0")'), 'RISK'],
  ['assignment completes before right read', sink('(id = "0") + id'), 'SAFE'],
  ['nested assignment result', 'let other = "0"; ' + sink('id + (other = (id = "0"))'), 'RISK'],
  ['compound assignment snapshots old value', 'id += (id = "0"); ' + sink('id'), 'RISK'],
  ['later overwrite removes input', 'id = "0"; ' + sink('id'), 'SAFE'],
  ['template substitutions read left to right', sink('`${id}${id = "0"}`'), 'RISK'],
  ['template overwrite before read', sink('`${id = "0"}${id}`'), 'SAFE'],
  ['conditional branches cannot overwrite each other', 'const sql = flag ? (id = "0") : id; ' + sink('sql'), 'RISK'],
  ['conditional state includes both paths', 'flag ? id : (id = "0"); ' + sink('id'), 'RISK'],
  ['conditional both branches overwrite', 'flag ? (id = "0") : (id = "1"); ' + sink('id'), 'SAFE'],
  ['short circuit false skips assignment', 'false && (id = "0"); ' + sink('id'), 'RISK'],
  ['short circuit true skips assignment', 'true || (id = "0"); ' + sink('id'), 'RISK'],
  ['nullish non-null skips assignment', '"" ?? (id = "0"); ' + sink('id'), 'RISK'],
  ['nullish null evaluates assignment', 'null ?? (id = "0"); ' + sink('id'), 'SAFE'],
  ['unknown logical condition merges state', 'flag && (id = "0"); ' + sink('id'), 'RISK'],
  ['if both branches overwrite', 'if(flag) id="0"; else id="1"; ' + sink('id'), 'SAFE'],
  ['if one branch overwrites', 'if(flag) id="0"; ' + sink('id'), 'RISK'],
  ['function arguments preserve earlier scalar', sink('first(id, id = "0")'), 'RISK', 'function first(a,b){return a;}'],
  ['function arguments see earlier assignment', sink('second(id = "0", id)'), 'SAFE', 'function second(a,b){return b;}'],
  ['receiver evaluated before argument mutation', 'const query=new URL(request.url).searchParams; let obj={sql:id}; ' + sink('obj.sql + (obj = {sql:"0"}).sql'), 'RISK'],
  ['block shadow does not overwrite outer input', '{ let id="0"; id="1"; } ' + sink('id'), 'RISK'],
  ['block temporal shadow cannot expose outer constant', 'let sql="SELECT 1"; { ' + sink('sql') + ' let sql=id; }', 'UNKNOWN'],
  ['function local cannot resolve same named module function', sink('helper(id)'), 'UNKNOWN', 'function helper(x){ return sanitize(x); }'],
  ['unknown transform is not static', sink('escapeSql(id)'), 'UNKNOWN'],
  ['unknown branch guard is not proven unguarded', 'if (!validate(id)) return; ' + sink('id'), 'UNKNOWN'],
  ['branch object mutation cannot contaminate sibling read', 'let obj={sql:id}; if(flag){obj.sql="0";} ' + sink('obj.sql'), 'UNKNOWN'],
  ['unsupported compound assignment cannot retain trusted tag', 'let sql="0"; sql ||= id; ' + sink('sql'), 'SAFE'],
  ['destructuring default cannot erase external input', 'const {sql = id} = {}; ' + sink('sql'), 'RISK'],
];
for (const [name, body, expected, functions] of pairs) test(name, () => expectFlow(run(body, functions), expected));

test('call receiver is captured before side-effecting arguments', () => {
  const r = run('let obj={db:env.DB}; return obj.db.prepare(id + (obj = {})).all();');
  assert.equal(r.sqlUses.length, 1);
  assert.equal(r.sqlUses[0].kind, 'INPUT_IN_QUERY');
});
test('unknown closure call cannot leave a formerly static local trusted', () => {
  expectFlow(run('let sql="SELECT 1"; const change=()=>{sql=id}; change(); ' + sink('sql')), 'UNKNOWN');
});
test('function fallthrough joins undefined instead of assuming one returned constant', () => {
  const r = run(sink('maybe(id)'), 'function maybe(x){ if(x) return "SELECT 1"; }');
  assert.equal(r.findings.length, 0);
});
test('constant truthiness follows the resulting expression, not one operand', () => {
  for (const condition of ['1 + -1', '`${""}`', '"" + ""']) {
    assert.equal(run(`if (${condition}) { ${sink('id')} }`).findings.length, 0, condition);
  }
  for (const condition of ['"prefix${0}"', '`prefix${0}`', '"x" + "x"']) {
    expectFlow(run(`if (${condition}) { ${sink('id')} }`), 'RISK');
  }
});
test('var declarations shadow module names before initialization', () => {
  const r = run('return env.DB.prepare(sql).all(); var sql=id;', 'const sql="SELECT 1";');
  assert.equal(r.findings.length, 0);
  assert.equal(r.sqlUses[0].trace.length, 0);
  const shadow = run('return env.DB.prepare(Number(id)).all(); var Number=identity;', 'function identity(x){return x;}');
  assert.equal(shadow.findings[0]?.confidence, 'MEDIUM');
});
test('unsupported callback mutating an alias invalidates the original object', () => {
  expectFlow(run('const a={sql:"SELECT 1"}; const b=a; const f=()=>{b.sql=id}; f(); ' + sink('a.sql')), 'UNKNOWN');
});
test('known function with branch-dependent heap mutation cannot leave caller SQL static', () => {
  expectFlow(run('const obj={sql:"SELECT 1"}; change(obj,id); '+sink('obj.sql'),
    'function change(obj,input){if(flag) obj.sql=input;}'), 'UNKNOWN');
});
test('default parameters and named function aliases preserve supported flow', () => {
  expectFlow(run(sink('copy(id)'), 'function copy(x,y=x){return y;}'), 'RISK');
  expectFlow(run('const copy=identity; '+sink('copy(id)'), 'function identity(x){return x;}'), 'RISK');
});
test('computed member reads capture the object before evaluating the key', () => {
  expectFlow(run('let box={sql:id}; '+sink('box[(box={sql:"0"}, "sql")]')), 'RISK');
});
test('uncertain side-effecting syntax never leaves subsequent SQL claimed static', () => {
  expectFlow(run('let sql="SELECT 1"; delete holder[sql=id]; '+sink('sql')), 'UNKNOWN');
});
test('both branches keep their own heap and disclose join uncertainty', () => {
  const r = run('let box={sql:"SELECT 1"}; if(flag){box.sql=id;} else {env.DB.prepare(box.sql).all();}');
  assert.equal(r.findings.length, 0);
  assert.equal(r.sqlUses[0].kind, 'STATIC_QUERY');
});
test('quoted and computed object binding keys preserve value flow and evaluation order', () => {
  expectFlow(run('const {"sql": query}={sql:id}; '+sink('query')), 'RISK');
  expectFlow(run('const {[id="sql"]: query}={sql:id}; '+sink('query')), 'RISK');
});
test('optional invocation cannot unconditionally erase earlier input', () => {
  expectFlow(run('maybe?.call(id="0"); '+sink('id')), 'UNKNOWN');
});
test('partial control coverage preserves observed static query and value binding', () => {
  for (const code of [
    'try { return env.DB.prepare("SELECT * FROM t WHERE id=?").bind(id).all(); } catch {}',
    'const exists=typeof id; maybe?.log(exists); return env.DB.prepare("SELECT * FROM t WHERE id=?").bind(id).all();',
  ]) {
    const r = run(code);
    assert.equal(r.status, 'PARTIAL');
    assert.equal(r.sqlUses[0].kind, 'PARAMETERIZED_QUERY');
    assert.ok(r.sqlUses[0].limitations.includes('EXECUTION_PATH_PARTIAL'));
    assert.equal(r.findings.length, 0);
  }
});
test('branch/closure traversal remains bounded and truncation is not a clean result', () => {
  const content = `export default {fetch(request,env){${input}
    ${Array.from({length:30}, (_,i)=>`if(flag${i}) id=id+"x";`).join('\n')}
    return env.DB.prepare(id).all();}}`;
  const r = analyze({files:[{filePath:'worker.ts',content}]}, {maxSteps:80});
  assert.equal(r.status, 'PARTIAL');
  assert.ok(r.files[0].limitations.includes('ANALYSIS_BUDGET_EXCEEDED'));
  assert.equal(r.sqlUses.length, 0);
});
