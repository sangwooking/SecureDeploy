"""Replay frozen source text through trusted workers; never load target modules."""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time

from application_track import digest, outside, read, relative, write
from node_worker_probe import packet, public_packet

BASELINE='186c186674ae4c4ab884e1dee82e4f11053ad328'
REPO=Path(__file__).resolve().parents[2]

def external_packets(root):
    packets=[]
    for project in read(root/'receipt.json'):
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',project['repository']):raise ValueError('REPOSITORY_IDENTITY')
        for stage in project['stages']:
            if stage['stage']not in {'before','after'}or not re.fullmatch('[0-9a-f]{40}',stage['commitSha']):raise ValueError('PINNED_STAGE')
            files=[];manifest=[]
            base=root/project['repository'].replace('/','--')/stage['stage']
            for entry in stage['files']:
                source=base/relative(entry['path'])
                if source.is_symlink() or not source.resolve().is_relative_to(base.resolve()):raise ValueError('SOURCE_PATH')
                data=source.read_bytes()
                if digest(data)!=entry['sha256']:raise ValueError('SOURCE_HASH')
                if source.suffix=='.js':files.append(dict(filePath=entry['path'],content=data.decode()))
                if entry['path']=='package.json':
                    deps=json.loads(data).get('dependencies',{})
                    manifest=[dict(filePath='package.json',**{key:deps[key]for key in ['express','mongodb']if isinstance(deps.get(key),str)and re.fullmatch(r'[A-Za-z0-9^~<>=.*+| -]{1,80}',deps[key])})]
            data=json.dumps(dict(files=files,nodeManifests=manifest),separators=(',',':')).encode()
            if len(data)>1200000:raise ValueError('PACKET_LIMIT')
            packets.append((project['repository']+':'+stage['stage'],stage['commitSha'],data))
    return packets

def execute(worker,data):
    start=time.monotonic()
    process=subprocess.Popen(['/usr/bin/time','-l','node','--max-old-space-size=192',str(REPO/'scripts/evaluation/node_probe_worker.mjs'),str(worker)],
        cwd=REPO,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        env={k:v for k,v in os.environ.items()if k in {'PATH','HOME','LANG','LC_ALL'}},start_new_session=True)
    try:stdout,stderr=process.communicate(data,timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid,signal.SIGKILL);process.wait();raise ValueError('WORKER_TIMEOUT')
    if process.returncode or len(stdout)>2000000:raise ValueError('WORKER_FAILED')
    result=json.loads(stdout);rss=re.search(rb'(\d+)\s+maximum resident set size',stderr)
    return dict(version=result['analyzerVersion'],status=result['status'],inputSha256=digest(data),
        wallMs=round((time.monotonic()-start)*1000),maximumRssBytes=int(rss.group(1))if rss else None,
        files=result['files'],findings=result['findings'],nodeUses=result.get('nodeUses',[]))

def evaluate(application_root,external_root,official_root,output):
    output=outside(output)
    if output.exists():raise ValueError('NEW_OUTPUT_REQUIRED')
    sha,data=packet(outside(application_root));packets=[('OWASP--NodeGoat',sha,data)]
    packets+=external_packets(outside(external_root))
    sha,data=public_packet(outside(official_root));packets.append(('expressjs--express-scope',sha,data))
    rows=[]
    with tempfile.TemporaryDirectory(prefix='securedeploy-provenance-baseline-')as directory:
        base=Path(directory)
        for name in ['analyzer.mjs','node-server.mjs','destination.mjs','exposure.mjs']:
            (base/name).write_bytes(subprocess.check_output(['git','show',BASELINE+':analyzers/typescript/'+name],cwd=REPO))
        (base/'node_modules').symlink_to(REPO/'analyzers/typescript/node_modules',target_is_directory=True)
        for ident,sha,data in packets:
            before=execute(base/'analyzer.mjs',data)
            after=execute(REPO/'analyzers/typescript/analyzer.mjs',data)
            rows.append(dict(project=ident,sourceCommit=sha,before=before,after=after))
    report=dict(schemaVersion=1,baseline=BASELINE,engineHead=subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip(),
        engineWorkingTreeDiffSha256=digest(subprocess.check_output(['git','diff','HEAD','--','src/main','analyzers'],cwd=REPO)),
        rows=rows,targetExecuted=False,userDatabaseUsed=False,externalVulnerabilityOrAiCalls=0,
        limits='Unchanged 192 MiB heap, file/text/AST/depth/step/result/time caps; isolated worker environment.',
        interpretation='CVE pairs are observed static source subsets, not blind whole-project truth; missing supported entries is NOT_SUPPORTED, never TN. Single timing/RSS samples are not performance guarantees.')
    write(output,report)
    print(json.dumps({'evaluatedInputs':len(rows),'sourceExecution':False,'findings':[{'project':r['project'],'before':len(r['before']['findings']),'after':len(r['after']['findings'])}for r in rows]}))

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    for name in ['application_root','external_root','official_root','output']:parser.add_argument(name)
    evaluate(**vars(parser.parse_args()))
