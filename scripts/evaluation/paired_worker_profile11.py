"""Sequential paired fresh-process static replay, never executes an input project."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import shutil
import subprocess
import time
from application_track import read, write


def percentile(values,q):
    if not values:raise ValueError('EMPTY_PROFILE')
    return sorted(values)[max(0,math.ceil(q*len(values))-1)]

def profile(spec):
    repos={key:Path(spec[key]).resolve() for key in ['before','after']}
    revisions={'before':spec.get('beforeRevision','e620a4cbf3ae1629ad58c9c9f8cc3cd83d1e167a'),'after':spec.get('afterRevision','2d88ce37e2a93b44fa10c07656efd33302971c67')}
    versions={'before':spec.get('beforeVersion','ts-server-v25'),'after':spec.get('afterVersion','ts-server-v26')}
    for key,root in repos.items():
        if not re.fullmatch('[a-f0-9]{40}',revisions[key]) or versions[key] not in ['ts-server-v25','ts-server-v26','ts-server-v27','ts-server-v28']:raise ValueError('PINNED_ENGINE_REQUIRED')
        subprocess.run(['git','merge-base','--is-ancestor','e620a4cbf3ae1629ad58c9c9f8cc3cd83d1e167a',revisions[key]],cwd=root,check=True,capture_output=True)
        # Only verified SecureDeploy analysis code, not a downloaded application's module.
        subprocess.run(['git','diff','--exit-code',revisions[key],'--','analyzers','scripts/evaluation/node_probe_worker.mjs'],cwd=root,check=True,capture_output=True)
        untracked=subprocess.check_output(['git','ls-files','--others','--exclude-standard','--','analyzers'],cwd=root)
        if untracked.strip():raise ValueError('UNVERIFIED_ANALYZER_CODE')
    trials=spec.get('trials',20)
    if not 20<=trials<=40:raise ValueError('PROFILE_TRIAL_LIMIT')
    node=shutil.which('node')
    if not node:raise RuntimeError('NODE_REQUIRED')
    env={k:v for k,v in os.environ.items() if k in ['PATH','HOME','LANG','LC_ALL']};rows=[]
    for item in spec['packets']:
        data=Path(item['path']).read_bytes()
        if len(data)>1200000 or hashlib.sha256(data).hexdigest()!=item['sha256']:raise ValueError('INPUT_HASH_OR_LIMIT')
        result={key:[] for key in repos};digests={};warmups={key:0 for key in repos}
        for trial in range(trials+2):
            order=['before','after'] if trial%2==0 else ['after','before']
            for key in order:
                root=repos[key];tool=root/'scripts/evaluation/node_probe_worker.mjs';analyzer=root/'analyzers/typescript/analyzer.mjs'
                started=time.monotonic();child=subprocess.Popen(['/usr/bin/time','-l',node,'--max-old-space-size=192',str(tool),str(analyzer)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,start_new_session=True)
                try:out,err=child.communicate(data,timeout=5)
                except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait();raise RuntimeError('WORKER_TIMEOUT')
                elapsed=round((time.monotonic()-started)*1000,2)
                if child.returncode or len(out)>2000000:raise RuntimeError('WORKER_FAILED')
                r=json.loads(out);expected=versions[key]
                if r['analyzerVersion']!=expected:raise ValueError('WORKER_VERSION')
                digest=hashlib.sha256(json.dumps(r,sort_keys=True,separators=(',',':')).encode()).hexdigest()
                if key in digests and digests[key]!=digest:raise ValueError('NONDETERMINISTIC_WORKER_OUTPUT')
                digests[key]=digest
                if trial<2:warmups[key]+=1;continue
                rss=re.search(rb'(\d+)\s+maximum resident set size',err)
                result[key].append(dict(wallMs=elapsed,maxRssBytes=int(rss[1]) if rss else None,budget=r['supabaseAnalysis']['budgetUsage'],files=len(r['files']),parsed=sum(f['parseStatus']=='PARSED' for f in r['files'])))
        rows.append(dict(project=item['project'],inputSha256=item['sha256'],trials=trials,warmups=warmups,runs=result,
          summary={key:dict(p50Ms=percentile([v['wallMs'] for v in values],.5),p95Ms=percentile([v['wallMs'] for v in values],.95),maxRssBytes=max(v['maxRssBytes'] or 0 for v in values)) for key,values in result.items()}))
    return dict(scope='STATIC_PARSED_SUBSET_PAIRED_FRESH_PROCESS_NOT_WHOLE_BACKEND_OR_COMPLETE_SQL',projects=rows,
      versions=versions,protocol='Same serialized packets and Node binary; alternating sequential before/after; two warmups each; no own concurrent evaluation or DB jobs. Host OS load/CPU affinity not controlled.',targetExecuted=False,failures=0,timeouts=0)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('spec',type=Path);p.add_argument('output',type=Path);a=p.parse_args();r=profile(read(a.spec));write(a.output,r)
    print(json.dumps([dict(project=x['project'],summary=x['summary']) for x in r['projects']]))
