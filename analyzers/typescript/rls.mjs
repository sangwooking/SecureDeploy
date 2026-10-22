// Deliberately limited PostgreSQL declaration grammar. Never executes SQL.
const OPS=['SELECT','INSERT','UPDATE','DELETE'];
const atom=kind=>({kind,columns:[]});
const unknown=()=>atom('UNKNOWN');
function combine(a,b,and){
  if(and&&(a.kind==='DENY'||b.kind==='DENY'))return atom('DENY');
  if(!and&&(a.kind==='ALLOW'||b.kind==='ALLOW'))return atom('ALLOW');
  if(a.kind===(and?'ALLOW':'DENY'))return b;
  if(b.kind===(and?'ALLOW':'DENY'))return a;
  if(a.kind==='UNKNOWN'||b.kind==='UNKNOWN')return unknown();
  if(a.kind===b.kind&&JSON.stringify(a.columns)===JSON.stringify(b.columns))return a;
  if(and&&[a.kind,b.kind].includes('AUTHENTICATION_ONLY'))return a.kind==='AUTHENTICATION_ONLY'?b:a;
  return unknown();
}

export function tokens(text,tick){
  const out=[];let i=0,line=1;
  const take=()=>{const c=text[i++];if(c==='\n')line++;return c;};
  while(i<text.length){
    tick();const start=line,c=text[i];
    if(/\s/.test(c)){take();continue;}
    if(text.startsWith('--',i)){while(i<text.length&&take()!=='\n');continue;}
    if(text.startsWith('/*',i)){
      i+=2;let depth=1;
      while(i<text.length&&depth){tick();if(text.startsWith('/*',i)){depth++;i+=2;}else if(text.startsWith('*/',i)){depth--;i+=2;}else take();}
      if(depth)throw Error('SQL_LEXICAL_ERROR');continue;
    }
    if(c==='"'||c==="'"){
      const quote=take();let value='',closed=false;
      while(i<text.length){tick();const x=take();if(x===quote){if(text[i]===quote){value+=take();continue;}closed=true;break;}value+=x;}
      if(!closed)throw Error('SQL_LEXICAL_ERROR');
      out.push({v:quote==='"'?value:'<literal>',kind:quote==='"'?'id':'string',quoted:quote==='"',line:start});continue;
    }
    const dollar=text.slice(i).match(/^\$(?:[A-Za-z_][\w]*)?\$/);
    if(dollar){
      const tag=dollar[0];i+=tag.length;const end=text.indexOf(tag,i);if(end<0)throw Error('SQL_LEXICAL_ERROR');
      while(i<end)take();i+=tag.length;out.push({v:'<body>',kind:'body',line:start});continue;
    }
    const id=text.slice(i).match(/^[A-Za-z_][A-Za-z0-9_$]*/);
    if(id){i+=id[0].length;out.push({v:id[0].toLowerCase(),kind:'id',line:start});}
    else {out.push({v:take(),kind:'symbol',line:start});}
    if(out.length>100000)throw Error('SQL_TOKEN_LIMIT');
  }
  return out;
}
const is=(t,v)=>t?.kind==='id'&&!t.quoted&&t.v===v;
function strip(ts){
  while(ts[0]?.v==='('&&ts.at(-1)?.v===')'){
    let n=0,end=-1;for(let i=0;i<ts.length;i++){if(ts[i].v==='(')n++;if(ts[i].v===')'&&--n===0){end=i;break;}}
    if(end!==ts.length-1)break;ts=ts.slice(1,-1);
  }return ts;
}
export function condition(original,depth=0){
  if(depth>12)return unknown();const ts=strip(original);if(!ts.length)return unknown();
  for(const op of ['or','and']){
    let n=0;for(let i=0;i<ts.length;i++){const t=ts[i];if(t.v==='(')n++;else if(t.v===')')n--;else if(!n&&is(t,op))return combine(condition(ts.slice(0,i),depth+1),condition(ts.slice(i+1),depth+1),op==='and');}
  }
  if(ts.length===1&&is(ts[0],'true'))return atom('ALLOW');
  if(ts.length===1&&is(ts[0],'false'))return atom('DENY');
  const uid=t=>{t=strip(t);if(is(t[0],'select'))t=strip(t.slice(1));return t.length===5&&is(t[0],'auth')&&t[1].v==='.'&&is(t[2],'uid')&&t[3].v==='('&&t[4].v===')';};
  const column=t=>{t=strip(t);return t.length===1&&t[0].kind==='id'&&!['true','false','null','current_user','current_role'].includes(t[0].v)?t[0].v:null;};
  let nesting=0;
  for(let i=0;i<ts.length;i++){
    if(ts[i].v==='(')nesting++;else if(ts[i].v===')')nesting--;
    else if(!nesting&&ts[i].v==='='){
      const a=ts.slice(0,i),b=ts.slice(i+1),c=uid(a)?column(b):uid(b)?column(a):null;
      if(c)return {kind:'UID_COLUMN_EQUALITY',columns:[c]};
      if(column(a)&&b.length===1&&(is(b[0],'true')||is(b[0],'false')))return {kind:'COLUMN_FILTER',columns:[column(a)]};
    }
  }
  if(ts.length>=4&&uid(ts.slice(0,-3))&&is(ts.at(-3),'is')&&is(ts.at(-2),'not')&&is(ts.at(-1),'null'))return atom('AUTHENTICATION_ONLY');
  return unknown();
}

class Cursor {
  constructor(ts){this.ts=ts;this.i=0;}
  eat(v){if(is(this.ts[this.i],v)||this.ts[this.i]?.kind==='symbol'&&this.ts[this.i].v===v){this.i++;return true;}return false;}
  require(v){if(!this.eat(v))throw Error('UNSUPPORTED_SQL');}
  id(){const t=this.ts[this.i++];if(t?.kind!=='id'||t.v.length>100||!/^\p{L}[\p{L}\p{N}_$ -]*$/u.test(t.v))throw Error('UNSUPPORTED_IDENTIFIER');return t.v;}
  table(){const schema=this.id();this.require('.');return schema+'.'+this.id();}
  end(){if(this.i!==this.ts.length)throw Error('UNSUPPORTED_SQL');}
  list(){const a=[this.id()];while(this.eat(','))a.push(this.id());return a;}
  expr(){this.require('(');const start=this.i;let n=1;while(this.i<this.ts.length&&n){const v=this.ts[this.i++].v;if(v==='(')n++;if(v===')')n--;if(n>30)throw Error('SQL_DEPTH_LIMIT');}if(n)throw Error('SQL_LEXICAL_ERROR');return condition(this.ts.slice(start,this.i-1));}
}

export function analyzePolicies(files,tick,workTick=tick){
  const tables=new Map(),results=[],limits=new Set(['DECLARATIONS_NOT_LIVE_DATABASE','ROLE_INHERITANCE_AND_ADMIN_BYPASS_UNKNOWN','CLI_NUMERIC_VERSION_LEXICAL_ORDER_NOT_DEPLOYMENT_PROOF']);
  const scopes=new Map();
  const migrationRoots=new Set(files.map(f=>f.filePath.match(/^(.*)supabase\/migrations\/[^/]+\.sql$/)?.[1]).filter(v=>v!==undefined));
  const ambiguousRoots=new Set(files.filter(f=>!f.filePath.includes('/migrations/')).map(f=>f.filePath.match(/^(.*)supabase\/(?:schemas\/|policies\/)?[^/]+\.sql$/)?.[1]??(f.filePath==='schema.sql'?'':null)).filter(v=>v!==null&&migrationRoots.has(v)));
  function table(scope,name,location){const key=scope+'|'+name;if(!tables.has(key)){if(tables.size>=200)throw Error('SQL_TABLE_LIMIT');tables.set(key,{scope,table:name,rls:'UNKNOWN',force:'UNKNOWN',location,policies:new Map(),grants:new Map(),grantLocations:[],uncertain:false});}return tables.get(key);}
  let statements=0,workExhausted=false;
  // CLI ListLocalMigrations uses directory lexical order and accepts numeric
  // version strings, not just generated 14-digit timestamps. Never run scripts.
  for(const file of [...files].sort((a,b)=>a.filePath<b.filePath?-1:a.filePath>b.filePath?1:0)){
    tick();const path=file.filePath,match=path.match(/^(.*)supabase\/migrations\/(\d+)_[^/]*\.sql$/);
    const migration=path.match(/^(.*)supabase\/migrations\/[^/]+\.sql$/);
    const scope=migration?migration[1]:'standalone:'+path;
    const state=scopes.get(scope)??{unknown:false,versions:new Set(),reasons:new Set()};scopes.set(scope,state);
    const uncertain=reason=>{state.unknown=true;state.reasons.add(reason);};
    if(ambiguousRoots.has(scope)||!migration&&ambiguousRoots.size)uncertain('MIGRATION_ORDER_MULTIPLE_SQL_SOURCES');
    if(migration&&!match)uncertain('MIGRATION_ORDER_UNSUPPORTED_FILENAME');
    if(match&&match[2].length===14&&path.endsWith('_init.sql')&&match[2]<'20211209000000')uncertain('MIGRATION_ORDER_LEGACY_INIT_SKIP_UNKNOWN');
    const location=line=>({filePath:path,line,column:1,functionName:'',kind:'RLS_DECLARATION'});
    if(file.status!=='SELECTED'){
      uncertain('MIGRATION_SOURCE_NOT_INSPECTED');results.push({filePath:path,status:file.status,statements:0,limitations:['SQL_SOURCE_NOT_INSPECTED',...(file.reason?[file.reason]:[])]});continue;
    }
    if(workExhausted){uncertain('MIGRATION_SOURCE_POLICY_BUDGET');results.push({filePath:path,status:'NOT_RUN',statements:0,limitations:['POLICY_STEP_BUDGET']});continue;}
    if(match&&state.versions.has(match[2]))uncertain('MIGRATION_VERSION_DUPLICATE');
    if(match)state.versions.add(match[2]);
    const row={filePath:path,status:'PARSED',statements:0,limitations:[]};results.push(row);
    try{
      const ts=tokens(file.content,workTick);let start=0;
      for(let end=0;end<=ts.length;end++)if(end===ts.length||ts[end].v===';'){
        const s=ts.slice(start,end);start=end+1;if(!s.length)continue;workTick();if(++statements>5000)throw Error('SQL_STATEMENT_LIMIT');row.statements++;
        const c=new Cursor(s);let target;
        try{
          if(c.eat('create')){
            if(c.eat('table')){
              const conditional=c.eat('if');if(conditional){c.require('not');c.require('exists');}
              const name=c.table();target=table(scope,name,location(s[0].line));c.require('(');
              // A CREATE TABLE body is not interpreted as top-level policy SQL.
              let n=1;while(c.i<s.length&&n){const v=s[c.i++].v;if(v==='(')n++;if(v===')')n--;}
              if(n)throw Error('SQL_LEXICAL_ERROR');c.end();
              if(target.created||conditional)target.uncertain=true;
              target.created=true;target.rls=conditional?'UNKNOWN':'DISABLED_BY_CREATE';
            }else if(c.eat('policy')){
              const name=c.id();c.require('on');target=table(scope,c.table(),location(s[0].line));
              const p={name,command:'ALL',mode:'PERMISSIVE',roles:['public'],using:atom('ALLOW'),check:null,location:location(s[0].line)};
              if(c.eat('as')){p.mode=c.eat('permissive')?'PERMISSIVE':c.eat('restrictive')?'RESTRICTIVE':null;if(!p.mode)throw Error('UNSUPPORTED_SQL');}
              if(c.eat('for')){if(s[c.i]?.quoted)throw Error('UNSUPPORTED_SQL');p.command=c.id().toUpperCase();if(![...OPS,'ALL'].includes(p.command))throw Error('UNSUPPORTED_SQL');}
              if(c.eat('to'))p.roles=c.list();
              if(p.roles.some(r=>['current_user','current_role','session_user'].includes(r)))target.uncertain=true;
              if(c.eat('using')){if(p.command==='INSERT')throw Error('INVALID_POLICY_CLAUSE');p.using=c.expr();}
              if(c.eat('with')){c.require('check');if(['SELECT','DELETE'].includes(p.command))throw Error('INVALID_POLICY_CLAUSE');p.check=c.expr();}
              c.end();if(target.policies.has(name))target.uncertain=true;target.policies.set(name,p);
            }else {row.status='PARTIAL';row.limitations.push('OTHER_SQL_NOT_INTERPRETED');}
          }else if(c.eat('alter')){
            if(c.eat('table')){
              c.eat('only');target=table(scope,c.table(),location(s[0].line));
              let action=c.eat('enable')?'ENABLED':c.eat('disable')?'DISABLED':c.eat('force')?'FORCED':c.eat('no')?(c.require('force'),'NOT_FORCED'):null;
              if(!action)throw Error('UNSUPPORTED_TABLE_CHANGE');
              c.require('row');c.require('level');c.require('security');c.end();
              if(['FORCED','NOT_FORCED'].includes(action))target.force=action;else{target.rls=action;target.location=location(s[0].line);}
            }else if(c.eat('policy')){
              const name=c.id();c.require('on');target=table(scope,c.table(),location(s[0].line));const p=target.policies.get(name);if(!p)throw Error('POLICY_BASE_MISSING');
              if(c.eat('rename')){c.require('to');const next=c.id();c.end();if(target.policies.has(next))throw Error('POLICY_RENAME_CONFLICT');target.policies.delete(name);p.name=next;target.policies.set(next,p);}
              else {if(c.eat('to'))p.roles=c.list();if(c.eat('using')){if(p.command==='INSERT')throw Error('INVALID_POLICY_CLAUSE');p.using=c.expr();}if(c.eat('with')){c.require('check');if(['SELECT','DELETE'].includes(p.command))throw Error('INVALID_POLICY_CLAUSE');p.check=c.expr();}c.end();}p.location=location(s[0].line);
              if(p.roles.some(r=>['current_user','current_role','session_user'].includes(r)))target.uncertain=true;
            }else throw Error('UNSUPPORTED_ROLE_OR_DEFAULT_CHANGE');
          }else if(c.eat('drop')){
            if(!c.eat('policy'))throw Error('UNSUPPORTED_DROP');const optional=c.eat('if');if(optional)c.require('exists');
            const name=c.id();c.require('on');target=table(scope,c.table(),location(s[0].line));c.eat('cascade')||c.eat('restrict');c.end();
            if(!optional&&!target.policies.has(name))target.uncertain=true;target.policies.delete(name);
          }else if(is(s[0],'grant')||is(s[0],'revoke')){
            if(is(s[1],'execute')){row.status='PARTIAL';row.limitations.push('FUNCTION_EXECUTE_PRIVILEGES_NOT_INTERPRETED');continue;}
            if(s[1]?.quoted)throw Error('UNSUPPORTED_GRANT');
            const grant=c.eat('grant');if(!grant)c.require('revoke');let ops;
            if(c.eat('all')){c.eat('privileges');ops=OPS;}else ops=c.list().map(x=>x.toUpperCase());
            if(ops.some(x=>!OPS.includes(x)))throw Error('UNSUPPORTED_GRANT');c.require('on');c.eat('table');target=table(scope,c.table(),location(s[0].line));
            c.require(grant?'to':'from');const roles=c.list();c.end();
            target.grantLocations.push(location(s[0].line));
            for(const role of roles){const set=target.grants.get(role)??new Set();for(const op of ops)grant?set.add(op):set.delete(op);target.grants.set(role,set);}
          }else if(c.eat('begin')||c.eat('commit'))c.end();
          else if(c.eat('do')||c.eat('set')||c.eat('reset')||c.eat('rollback'))throw Error('DYNAMIC_OR_TRANSACTION_STATE_UNKNOWN');
          else {row.status='PARTIAL';row.limitations.push('OTHER_SQL_NOT_INTERPRETED');}
        }catch{row.status='PARTIAL';row.limitations.push('UNSUPPORTED_SQL_DECLARATION');if(target)target.uncertain=true;else uncertain('MIGRATION_SQL_EFFECT_UNKNOWN');}
      }
    }catch(error){
      uncertain('MIGRATION_SOURCE_PARSE_OR_BUDGET_FAILURE');
      if(error?.message==='POLICY_STEP_BUDGET'){
        row.status='LIMIT_EXCEEDED';row.limitations.push('POLICY_STEP_BUDGET');
        workExhausted=true;limits.add('POLICY_STEP_BUDGET');
      }else{row.status='PARSE_FAILED';row.limitations.push('SQL_LEXICAL_OR_RESOURCE_LIMIT');}
    }
    row.limitations=[...new Set(row.limitations)];
  }
  const output=[];
  for(const t of tables.values()){
    tick();const uncertain=!t.created||t.uncertain||scopes.get(t.scope)?.unknown;
    const policies=[...t.policies.values()].map(p=>({...p,check:p.check??(['ALL','UPDATE'].includes(p.command)?p.using:atom('ALLOW'))}));
    const operations=[];
    for(const role of ['anon','authenticated'])for(const op of OPS){
      const applicable=policies.filter(p=>[op,'ALL'].includes(p.command)&&(p.roles.includes(role)||p.roles.includes('public')));
      const merge=key=>{const permissive=applicable.filter(p=>p.mode==='PERMISSIVE').reduce((a,p)=>combine(a,p[key],false),atom('DENY'));
        return applicable.filter(p=>p.mode==='RESTRICTIVE').reduce((a,p)=>combine(a,p[key],true),permissive);};
      const using=merge('using'),check=merge('check'),grant=t.grants.get(role)?.has(op)||t.grants.get('public')?.has(op)||false;
      const broad=v=>v.kind==='ALLOW'||role==='authenticated'&&v.kind==='AUTHENTICATION_ONLY';
      const state=uncertain?'UNKNOWN':t.rls==='ENABLED'?(op==='INSERT'?check.kind:op==='UPDATE'?combine(using,check,true).kind:using.kind):t.rls;
      const candidate=!uncertain&&grant&&op!=='SELECT'&&(['DISABLED','DISABLED_BY_CREATE'].includes(t.rls)||t.rls==='ENABLED'&&(op==='INSERT'?broad(check):op==='DELETE'?broad(using):broad(using)&&broad(check)));
      operations.push({role,operation:op,grant:grant?'EXPLICIT_GRANT':'NOT_ESTABLISHED',using:using.kind,check:check.kind,
        columns:[...new Set([...using.columns,...check.columns])],state,candidate,
        policyLocations:applicable.map(p=>p.location)});
    }
    output.push({scope:t.scope,table:t.table,rls:uncertain?'UNKNOWN':t.rls,force:t.force,location:t.location,grantLocations:t.grantLocations,policies,operations,
      limitations:['DECLARATIONS_NOT_LIVE_DATABASE',...(uncertain?['MIGRATION_OR_SQL_CONTEXT_UNKNOWN',...scopes.get(t.scope).reasons]:[])]});
  }
  return {files:results,tables:output,limitations:[...limits]};
}
