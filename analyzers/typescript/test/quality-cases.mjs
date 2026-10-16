// Held-out combinations fixed before the state-tracking implementation changes.
// Labels describe explicit SQL-string input flow, not runtime exploitability.
export const qualityCases = [
  ['saved-scalar', 'RISK', 'const saved=q; q="0"; return db.prepare(saved).all();'],
  ['returned-second-argument', 'RISK', 'return db.prepare(choose(q="0",body)).all();', 'function choose(a,b){return b;}'],
  ['returning-bound-statement', 'SAFE', 'return db.prepare("SELECT * FROM t WHERE id=?").bind(q).all();'],
  ['early-reject-literal-list', 'SAFE', 'if(!["name","id"].includes(q)) return; return db.prepare("SELECT "+q+" FROM t").all();'],
  ['conditional-constant-selection', 'SAFE', 'const column=q ? "id" : "name"; return db.prepare("SELECT "+column+" FROM t").all();'],
  ['nonterminating-check', 'RISK', '["name","id"].includes(q); return db.prepare(q).all();'],
  ['guard-reassigned-input', 'RISK', 'if(q!=="id") return; q=body; return db.prepare(q).all();'],
  ['logical-or-overwrite', 'SAFE', 'false || (q="SELECT 1"); return db.prepare(q).all();'],
  ['logical-and-overwrite', 'SAFE', 'true && (q="SELECT 1"); return db.prepare(q).all();'],
  ['logical-or-skipped-write', 'RISK', '1 || (q="SELECT 1"); return db.prepare(q).all();'],
  ['known-branch-only', 'SAFE', 'const sql=0 ? body : "SELECT 1"; return db.prepare(sql).all();'],
  ['separate-branch-environments', 'RISK', 'let sql=q; const v=flag ? (sql="0") : sql; return db.prepare(v).all();'],
  ['unresolved-normalization', 'UNKNOWN', 'return db.prepare(normalize(body)).all();'],
  ['unresolved-predicate', 'UNKNOWN', 'if (!allow(q)) return; return db.prepare(q).all();'],
  ['unknown-object-mutation', 'UNKNOWN', 'const opts={sql:"SELECT 1"}; alter(opts,q); return db.prepare(opts.sql).all();'],
  ['shadowed-numeric-converter', 'RISK', 'const Number=identity; return db.prepare(Number(q)).all();', 'function identity(x){return x;}'],
  ['nested-scalar-shadow', 'SAFE', 'let sql="SELECT 1"; { let sql=q; sql=body; } return db.prepare(sql).all();'],
  ['bind-after-template', 'RISK', 'return db.prepare(`SELECT * FROM t WHERE id=${q}`).bind(1).all();'],
  ['unsupported-callback', 'UNKNOWN', 'let sql="SELECT 1"; [q].forEach(x=>{sql=x}); return db.prepare(sql).all();'],
  ['bounded-recursion', 'UNKNOWN', 'return db.prepare(recur(q)).all();', 'function recur(x){return recur(x);}'],
];
