"""Trusted static subprocess only; input never imported or executed."""
import json,sys,pathlib,subprocess,hashlib,time,resource
root=pathlib.Path(__file__).parent
cases=json.loads((root/'accuracy02-large-inputs.json').read_text())['cases']
rows=[]
for c in cases:
 start=time.perf_counter();p=subprocess.run([sys.executable,'-I','-S','-B',sys.argv[1]],input=json.dumps({'files':c['files']}),capture_output=True,text=True,timeout=10)
 a=json.loads(p.stdout) if p.returncode==0 else None
 found=[f for f in a['findings'] if f['ruleId']==c['rule']] if a else []
 classification='UNKNOWN' if c['truth'] is None or not a else ('TP' if found else 'FN') if c['truth'] else ('FP' if found else 'TN')
 rows.append(dict(id=c['id'],truth=c['truth'],cohort=c['cohort'],classification=classification,selected=len(c['files']),parsed=sum(f['parseStatus']=='PARSED' for f in a['files']) if a else 0,entries=sum(f['entrypoints']for f in a['files'])if a else 0,functions=sum(f['functionsAnalyzed']for f in a['files'])if a else 0,partial=a and a['status']=='PARTIAL',sourceHashes={f['filePath']:hashlib.sha256(f['content'].encode()).hexdigest()for f in c['files']},analysis=a,refusal=None if a else 'SUBPROCESS_INPUT_REFUSED',wallMs=(time.perf_counter()-start)*1000))
result=dict(scope='Preimplementation own large-file inputs, not blinded',counts={k:sum(r['classification']==k for r in rows)for k in ['TP','FP','TN','FN','UNKNOWN']},rows=rows)
pathlib.Path(sys.argv[2]).write_text(json.dumps(result,indent=2));print(result['counts'])
