const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {spawn,execFileSync}=require('node:child_process');
const readline=require('node:readline');process.umask(0o077);
const old='/Users/sangwoo__o/.local/share/securedeploy/cutover/2026-10-28-336';
const root='/private/tmp/securedeploy-ready02-private';
const repo='/private/tmp/securedeploy-routes35i';
const settings=JSON.parse(fs.readFileSync(old+'/runtime-settings-private.json'));
const inv=JSON.parse(fs.readFileSync(old+'/runtime-inventory-private.json'));
const hash=f=>crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');
const write=(p,d)=>fs.writeFileSync(root+'/'+p,JSON.stringify(d,null,2),{mode:0o600});
const read=p=>JSON.parse(fs.readFileSync(root+'/'+p));
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const baseEnv=Object.fromEntries(Object.entries(settings.environment).filter(([k])=>['PATH','JAVA_HOME','HOME','LANG','LC_ALL','TMPDIR'].includes(k)));
const dburl=new URL(settings.environment.DB_URL.replace(/^jdbc:/,''));
if(dburl.protocol!=='postgresql:'||!['localhost','127.0.0.1'].includes(dburl.hostname))throw Error('LOCAL_POSTGRES_REQUIRED');
const pgEnv={...baseEnv,PGHOST:dburl.hostname,PGPORT:dburl.port||'5432',PGDATABASE:decodeURIComponent(dburl.pathname.slice(1)),PGUSER:settings.environment.DB_USERNAME,PGPASSWORD:settings.environment.DB_PASSWORD,PGCONNECT_TIMEOUT:'5'};
const psql='/opt/homebrew/bin/psql',pgdump='/opt/homebrew/bin/pg_dump',pgrestore='/opt/homebrew/bin/pg_restore';
function sql(q){return execFileSync(psql,['-X','-qAt','-v','ON_ERROR_STOP=1','-c',q],{env:pgEnv,encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();}
const quote=s=>'"'+s.replaceAll('"','""')+'"';
async function database(label,backup){
 const tables=JSON.parse(sql("select coalesce(json_agg(tablename order by tablename),'[]'::json) from pg_tables where schemaname='public'"));
 const p=spawn(psql,['-X','-qAt','-v','ON_ERROR_STOP=1'],{env:pgEnv,stdio:['pipe','pipe','pipe']});const errors=[];p.stderr.on('data',b=>errors.push(b));
 let waiting=[];const lines=[];const rl=readline.createInterface({input:p.stdout});rl.on('line',line=>{lines.push(line);for(const w of waiting)w();waiting=[];});
 const until=async f=>{for(let i=0;i<100;i++){if(f())return;await Promise.race([new Promise(r=>waiting.push(r)),sleep(100)]);}throw Error('DATABASE_READ_TIMEOUT');};
 p.stdin.write("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\nSELECT 'SNAP:'||pg_export_snapshot();\n");await until(()=>lines.some(l=>l.startsWith('SNAP:')));
 const snapshot=lines.find(l=>l.startsWith('SNAP:')).slice(5);
 for(const t of tables)p.stdin.write(`SELECT json_build_object('table',${"'"+t.replaceAll("'","''")+"'"},'count',count(*),'hash',md5(coalesce(string_agg(h,'' ORDER BY h),''))) FROM (SELECT md5(row_to_json(t)::text) h FROM public.${quote(t)} t) x;\n`);
 p.stdin.write("SELECT 'METADATA_DONE';\n");await until(()=>lines.includes('METADATA_DONE'));
 const inventory=lines.filter(l=>l.startsWith('{')).map(l=>JSON.parse(l));
 if(backup){
  const file=root+'/database-'+label+'.dump';if(fs.existsSync(file))throw Error('BACKUP_ALREADY_EXISTS');
  execFileSync(pgdump,['--format=custom','--snapshot='+snapshot,'--file='+file],{env:pgEnv,stdio:['ignore','ignore','pipe']});
  execFileSync(pgrestore,['--list',file],{env:baseEnv,stdio:['ignore','ignore','pipe']});
  execFileSync(pgrestore,['--file=/dev/null',file],{env:baseEnv,stdio:['ignore','ignore','pipe']});
  write('backup-'+label+'.json',{file,sha256:hash(file),bytes:fs.statSync(file).size,consistentExportedSnapshot:true,archiveFullyDecoded:true,restoreIntoDatabaseTested:false,createdAt:Date.now()});
 }
 p.stdin.end('ROLLBACK;\n');const code=await new Promise(r=>p.on('close',r));if(code)throw Error('DATABASE_INVENTORY_FAILED');
 write('database-'+label+'-private.json',inventory);console.log(JSON.stringify({database:label,tables:inventory.map(x=>({table:x.table,count:x.count})),rowHashesRecorded:true,backup:!!backup}));
}

(async()=>{if(!fs.existsSync(root))fs.mkdirSync(root,{mode:0o700});await database(process.argv[2]||'ready02-before',true);})().catch(e=>{console.error(e.code||'DB_CHECK_FAILED');process.exitCode=1;});
