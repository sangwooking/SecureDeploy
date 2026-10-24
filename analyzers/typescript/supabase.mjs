import {analyzePolicies} from './rls.mjs';
import {linkSupabaseEvidence} from './supabase-evidence.mjs';

export function supabaseAnalysis({ts,modules,input,tick,precomputedPolicies,sourceImports}){
  const unavailable=reason=>({schemaVersion:1,analyzerVersion:'supabase-rls-v2',status:'PARTIAL',files:(input.policyFiles??[]).slice(0,100).map(f=>({filePath:f.filePath,status:'NOT_RUN',statements:0,limitations:[reason]})),tables:[],clients:[],accesses:[],findings:[],limitations:['DECLARATIONS_NOT_LIVE_DATABASE',reason]});
  const location=(node,mod,kind)=>{const p=mod.ast.getLineAndCharacterOfPosition(node.getStart(mod.ast));return {filePath:mod.filePath,line:p.line+1,column:p.character+1,functionName:'',kind};};
  const clients=[],accesses=[],limitations=['DECLARATIONS_NOT_LIVE_DATABASE','CLIENT_CALL_NOT_AUTHENTICATION_OR_RUNTIME_PROOF'];
  let policies;
  try{
    policies=precomputedPolicies??analyzePolicies(input.policyFiles??[],()=>tick());
    if(input.policyInventoryComplete===false){
      policies.limitations.push('SQL_FILE_INVENTORY_TRUNCATED');
      for(const t of policies.tables){t.rls='UNKNOWN';t.limitations.push('SQL_FILE_INVENTORY_TRUNCATED');for(const o of t.operations){o.state='UNKNOWN';o.candidate=false;}}
    }
    const caches=new Map();
    const unwrap=n=>{while(n&&(ts.isAsExpression(n)||ts.isNonNullExpression(n)||ts.isParenthesizedExpression(n)))n=n.expression;return n;};
    const official=spec=>spec==='@supabase/supabase-js'||/^npm:@supabase\/supabase-js@2(?:\.\d+){0,2}$/.test(spec)
      ||/^https:\/\/esm\.sh\/@supabase\/supabase-js@2(?:\.\d+){0,2}$/.test(spec);
    for(const mod of modules.values()){
      if(!mod.hasSupabaseSyntax)continue;
      if(mod.syntaxIndex){caches.set(mod,mod.syntaxIndex);continue;}
      const declarations=new Map(),writes=new Set(),nodes=[],typeOnly=new Set();
      const visit=n=>{tick();if(ts.isCallExpression(n))nodes.push(n);if(n.name&&ts.isIdentifier(n.name)&&[ts.isVariableDeclaration,ts.isParameter,ts.isFunctionDeclaration,ts.isClassDeclaration,ts.isBindingElement].some(f=>f(n))){const a=declarations.get(n.name.text)??[];a.push(n);declarations.set(n.name.text,a);}
        if(ts.isImportDeclaration(n)){if(n.importClause?.isTypeOnly&&n.importClause.name)typeOnly.add(n.importClause.name.text);for(const e of n.importClause?.namedBindings?.elements??[])if(n.importClause.isTypeOnly||e.isTypeOnly)typeOnly.add(e.name.text);}
        if(ts.isBinaryExpression(n)&&ts.isAssignmentOperator(n.operatorToken.kind)){let x=n.left;while(ts.isPropertyAccessExpression(x)||ts.isElementAccessExpression(x))x=x.expression;if(ts.isIdentifier(x))writes.add(x.text);}
        ts.forEachChild(n,visit);};visit(mod.ast);caches.set(mod,{declarations,writes,nodes,typeOnly});
    }
    function resolve(mod,original,seen=new Set(),depth=0){
      tick();const node=unwrap(original);if(!node||depth>3||seen.has(node))return null;seen=new Set([...seen,node]);
      const cache=caches.get(mod);if(!cache)return null;
      if(ts.isIdentifier(node)){
        if(cache.writes.has(node.text)||cache.typeOnly.has(node.text))return null;
        const ds=cache.declarations.get(node.text)??[];
        if(ds.length===1&&ts.isVariableDeclaration(ds[0])&&(ds[0].parent.flags&ts.NodeFlags.Const))return resolve(mod,ds[0].initializer,seen,depth+1);
        if(ds.length)return null;
        const imp=mod.imports.get(node.text);
        if(imp&&!imp.spec.startsWith('.')){
          const target=sourceImports?.target(mod,imp.spec);
          const d=target&&caches.get(target)?.declarations.get(imp.exported);
          if(d?.length===1&&ts.isVariableDeclaration(d[0])&&d[0].parent.parent.modifiers?.some(m=>m.kind===ts.SyntaxKind.ExportKeyword))return resolve(target,d[0].name,seen,depth+1);
        }
        if(imp?.spec.startsWith('.')){
          const base=mod.filePath.split('/').slice(0,-1);for(const p of imp.spec.split('/')){if(p==='..')base.pop();else if(p!=='.')base.push(p);}
          const path=base.join('/');const target=[path,path+'.ts',path+'.tsx',path+'.js',path+'/index.ts'].map(p=>modules.get(p)).find(Boolean);
          if(target){const d=caches.get(target)?.declarations.get(imp.exported);if(d?.length===1&&ts.isVariableDeclaration(d[0])&&d[0].parent.parent.modifiers?.some(m=>m.kind===ts.SyntaxKind.ExportKeyword))return resolve(target,d[0].name,seen,depth+1);}
        }
      }
      if(ts.isCallExpression(node)&&ts.isIdentifier(node.expression)){
        const imp=mod.imports.get(node.expression.text);
        if(imp?.exported==='createClient'&&official(imp.spec)&&!sourceImports?.shadows(mod,imp.spec)&&!cache.typeOnly.has(node.expression.text)&&!cache.declarations.has(node.expression.text)&&!cache.writes.has(node.expression.text)&&node.arguments.length>=2&&node.arguments.length<=3){
          const loc=location(node,mod,'SUPABASE_CLIENT_DECLARATION');
          let key=unwrap(node.arguments[1]),steps=0;
          while(key&&ts.isIdentifier(key)&&steps++<3){const ds=cache.declarations.get(key.text);if(ds?.length!==1||cache.writes.has(key.text)||!ts.isVariableDeclaration(ds[0]))break;key=unwrap(ds[0].initializer);}
          let keySource='UNKNOWN',label;
          if(key&&ts.isPropertyAccessExpression(key)){
            const root=key.expression.getText(mod.ast);
            if(root==='import.meta.env'||root==='process.env'&&!cache.declarations.has('process')&&!cache.writes.has('process'))label=key.name.text;
          }else if(key&&ts.isCallExpression(key)&&key.expression.getText(mod.ast)==='Deno.env.get'&&!cache.declarations.has('Deno')&&!cache.writes.has('Deno')&&key.arguments.length===1&&ts.isStringLiteral(key.arguments[0]))label=key.arguments[0].text;
          if(label)keySource=/(?:SERVICE_ROLE|SECRET_KEY)/i.test(label)?'SERVER_KEY_NAME_HINT':/(?:PUBLISHABLE|ANON)/i.test(label)?'PUBLIC_KEY_NAME_HINT':'ENVIRONMENT_REFERENCE_UNKNOWN';
          const record={location:loc,keySource,authContext:node.arguments.length===3?'OPTIONS_OR_AUTH_OVERRIDE_NOT_EVALUATED':'SESSION_AND_AUTH_HEADERS_UNKNOWN',limitations:['KEY_NAME_NOT_ACTUAL_ROLE_PROOF','LIBRARY_VERSION_AND_RUNTIME_UNKNOWN']};
          if(!clients.some(c=>c.location.filePath===loc.filePath&&c.location.line===loc.line&&c.location.column===loc.column)){if(clients.length>=100)throw Error('SUPABASE_RESULT_LIMIT');clients.push(record);}return record;
        }
      }
      return null;
    }
    for(const [mod,cache] of caches)for(const node of cache.nodes){
      tick();if(ts.isCallExpression(node)&&ts.isIdentifier(node.expression))resolve(mod,node);
      if(!ts.isCallExpression(node)||!ts.isPropertyAccessExpression(node.expression)||node.expression.name.text!=='from'||node.arguments.length!==1||!ts.isStringLiteral(node.arguments[0]))continue;
      const name=node.arguments[0].text;if(!/^[A-Za-z_][A-Za-z0-9_]{0,99}$/.test(name))continue;
      let outer=node,operation=null;
      while(ts.isPropertyAccessExpression(outer.parent)&&outer.parent.expression===outer&&ts.isCallExpression(outer.parent.parent)){
        outer=outer.parent.parent;const method=outer.expression.name.text;
        if(!operation&&['select','insert','update','delete','upsert'].includes(method))operation=method.toUpperCase();
      }
      if(!operation)continue;
      const client=resolve(mod,node.expression.expression),scope=(mod.filePath.match(/^(.*?)(?:src\/|supabase\/)/)?.[1])??'';
      const table='public.'+name;
      const declared=policies.tables.find(t=>t.scope===scope&&t.table===table);
      if(accesses.length>=200)throw Error('SUPABASE_RESULT_LIMIT');
      accesses.push({location:location(outer,mod,'SUPABASE_DATA_ACCESS'),table,operation,
        clientStatus:client?'CLIENT_DECLARATION_LINKED':'CLIENT_ORIGIN_UNKNOWN',clientLocation:client?.location??null,
        keySource:client?.keySource??'UNKNOWN',policyStatus:declared?'TABLE_DECLARATION_FOUND':'POLICY_CONTEXT_MISSING',
        policyLocation:declared?.location??null,limitations:['CALL_CHAIN_NOT_EXECUTION_PROOF','APPLICATION_USER_AND_DEPLOYED_POLICY_UNKNOWN',...(client?[]:['IMPORT_ALIAS_FACTORY_OR_CONTEXT_NOT_RESOLVED'])]});
    }
  }catch(error){
    if(!policies)return unavailable('SQL_OR_AST_ANALYSIS_LIMIT');
    clients.length=0;accesses.length=0;
    limitations.push(['SUPABASE_BUDGET','CLIENT_STEP_BUDGET'].includes(error?.message)?'CLIENT_AST_BUDGET_LIMIT':'CLIENT_AST_CONTEXT_NOT_COMPLETED');
    if(error?.message==='CLIENT_STEP_BUDGET')limitations.push('CLIENT_STEP_BUDGET');
  }
  const findings=[];
  for(const table of policies.tables){
    const broad=table.operations.filter(o=>o.candidate);
    if(!broad.length)continue;
    const location=table.rls==='ENABLED'?(broad[0].policyLocations[0]??table.location):table.location;
    findings.push({findingId:`supabase-rls:${table.scope}:${table.table}`,ruleId:'SUPABASE_BROAD_WRITE_DECLARATION',priority:'REVIEW_REQUIRED',comparisonPolicy:'NOT_COMPARED',
      table:table.table,location,roles:[...new Set(broad.map(o=>o.role))],operations:[...new Set(broad.map(o=>o.operation))],
      evidenceLocations:[location,table.location,...table.grantLocations,...broad.flatMap(o=>o.policyLocations)].filter((v,i,a)=>a.findIndex(x=>JSON.stringify(x)===JSON.stringify(v))===i),
      title:'사용자별 수정 권한이 넓게 선언되어 있습니다',
      reason:'명시적 쓰기 권한과 행 접근 선언에서 사용자별 제한이 없는 작업을 확인했습니다. 의도적인 공유 데이터인지와 운영 적용 상태는 별도 확인이 필요합니다.',
      recommendation:'공유 데이터인지 먼저 확인하고, 사용자 전용 데이터라면 해당 작업의 기존 행 조건(USING)과 새 행 조건(WITH CHECK)에 실제 소유자 컬럼과 auth.uid() 비교를 적용하세요. 여러 permissive 정책과 GRANT도 함께 검토하세요.',
      verificationSteps:['격리 테스트 환경에서 사용자 A·B의 조회·수정·삭제와 소유자 변경을 각각 확인하세요.','익명 사용자와 관리자 경로를 따로 검사하고 실제 적용 migration·GRANT·역할을 대조한 뒤 재검사하세요.'],
      limitations:['DECLARATIONS_NOT_LIVE_DATABASE','PUBLIC_OR_SHARED_DATA_INTENT_UNKNOWN','REQUEST_EXECUTION_AND_EXPLOIT_NOT_VERIFIED']});
  }
  const snapshot={schemaVersion:1,analyzerVersion:'supabase-rls-v2',status:policies.files.length||accesses.length||clients.length?'PARTIAL':'NOT_APPLICABLE',
    ...policies,clients,accesses,findings,limitations:[...policies.limitations,...limitations]};
  linkSupabaseEvidence({ts,modules,snapshot,tick,sourceImports});
  return Buffer.byteLength(JSON.stringify(snapshot))>300000?unavailable('SUPABASE_OUTPUT_LIMIT'):snapshot;
}
