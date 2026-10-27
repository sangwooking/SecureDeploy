"""New engine observations of unchanged #13 controls; never rewrites the v28 oracle."""
import argparse
from collections import Counter
import json
from pathlib import Path
import shutil
from application_track import outside,write
from authorization_intent13 import digest,interpret
from intent13_cases import freeze
from mongoose18 import run


def replay(repo):
    worker=repo/'analyzers/typescript';node=shutil.which('node');rows=[]
    for c in freeze()['cases']:
        if digest(c['packet'])!=c['sourceSha256']:raise ValueError('FROZEN_SOURCE_CHANGED')
        args=['--allow-fs-read='+str(worker),str(worker/'worker.mjs')]
        a,b=[run(node,args,json.dumps(c['packet']).encode()) for _ in range(2)]
        if a!=b:raise ValueError('REPEAT_MISMATCH')
        if a['analyzerVersion']!='ts-server-v40' or a['supabaseAnalysis']['analyzerVersion']!='supabase-rls-v4':raise ValueError('ENGINE_VERSION')
        snapshot=a['supabaseAnalysis'];source=interpret(snapshot,None,c['sourceSha256'],'SOURCE_ONLY')
        declared=interpret(snapshot,c['intent'],c['sourceSha256'],'DECLARED_INTENT')
        rows.append(dict(caseId=c['caseId'],sourceSha256=c['sourceSha256'],sourceOnly=source['status'],
                         declaredIntent=declared['status'],originalExpected=c['expected'],matches=declared['status']==c['expected']))
    return dict(worker='ts-server-v40',rls='supabase-rls-v4',cases=len(rows),
                sourceStates=dict(Counter(r['sourceOnly'] for r in rows)),intentStates=dict(Counter(r['declaredIntent'] for r in rows)),
                originalExpectationMatches=sum(r['matches'] for r in rows),rows=rows,repeatIdentical=True,
                meaning='Unchanged synthetic intent interpreter on new engine; no owner approval, deployed DB proof or vulnerability accuracy claim',
                originalV28ReceiptRewritten=False,newRealTP=0)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--repo',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    result=replay(a.repo.resolve());write(outside(a.output),result)
    print(json.dumps({k:v for k,v in result.items() if k!='rows'}))
