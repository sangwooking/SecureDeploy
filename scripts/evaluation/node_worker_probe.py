"""Frozen NodeGoat text to baseline/current trusted workers. Never execute target code."""
import argparse,json,os,re,signal,subprocess,tempfile,time
from pathlib import Path
from application_track import read,write,outside,digest,relative

BASELINE='cd80bfa4b4c0c1d6a249b4d641a3acea752a663b'
REPO=Path(__file__).resolve().parents[2]

def packet(root):
    plan=read(root/'application-plan.json');raw=read(root/'hardening3-after.json')
    if raw['planSha256']!=digest((root/'application-plan.json').read_bytes()):raise ValueError('PLAN_CHANGED')
    project=next(p for p in plan['projects']if p['projectId']=='OWASP--NodeGoat')
    old=next(p for p in raw['projects']if p['projectId']==project['projectId'])['runs'][0]['typescript']
    index={f['path']:f for f in project['files']};base=root/'sources'/project['projectId']
    def source(name):
        path=base/relative(name)
        if path.is_symlink() or not path.resolve().is_relative_to(base.resolve()):raise ValueError('SOURCE_PATH')
        data=path.read_bytes()
        if digest(data)!=index[name]['sha256']:raise ValueError('SOURCE_HASH')
        return '\n'.join(data.decode().splitlines())
    files=[dict(filePath=f['filePath'],content=source(f['filePath']))for f in old['files']if f['parseStatus']=='PARSED']
    if len(files)>100 or any(len(f['content'])>100000 for f in files)or sum(len(f['content'])for f in files)>1000000:raise ValueError('SOURCE_LIMIT')
    package=json.loads(source('package.json'))
    return project['commitSha'],json.dumps(dict(files=files,nodeManifests=[dict(filePath='package.json',mongodb=package['dependencies']['mongodb'],express=package['dependencies']['express'])]),ensure_ascii=False,separators=(',',':')).encode()

def public_packet(root):
    receipt=read(root/'receipt.json');files=[]
    for entry in receipt['files']:
        path=root/relative(entry['path'])
        if path.is_symlink()or not path.resolve().is_relative_to(root.resolve()):raise ValueError('PUBLIC_SOURCE_PATH')
        data=path.read_bytes()
        if digest(data)!=entry['sha256']:raise ValueError('PUBLIC_SOURCE_HASH')
        if path.suffix=='.js':files.append(dict(filePath=entry['path'],content='\n'.join(data.decode().splitlines())))
    if len(files)!=2 or any(len(f['content'])>100000 for f in files):raise ValueError('PUBLIC_SELECTION')
    return receipt['commitSha'],json.dumps(dict(files=files),separators=(',',':')).encode()

def probe(root,output,public_root=None):
    root=outside(root);output=outside(output)
    if output.exists():raise ValueError('NEW_OUTPUT_REQUIRED')
    if subprocess.check_output(['git','diff','HEAD','--','src/main','analyzers'],cwd=REPO).strip():raise ValueError('COMMITTED_ENGINE_REQUIRED')
    sha,data=packet(root);results=[];inputs=[('OWASP--NodeGoat',sha,data)]
    if public_root:
        public_sha,public_data=public_packet(outside(public_root));inputs.append(('expressjs--express-scope',public_sha,public_data))
    with tempfile.TemporaryDirectory(prefix='securedeploy-trusted-node-baseline-')as directory:
        directory=Path(directory)
        for name in ['analyzer.mjs','destination.mjs','exposure.mjs']:
            (directory/name).write_bytes(subprocess.check_output(['git','show',BASELINE+':analyzers/typescript/'+name],cwd=REPO))
        (directory/'node_modules').symlink_to(REPO/'analyzers/typescript/node_modules',target_is_directory=True)
        for project,source_sha,data in inputs:
          for stage,worker in [('before',directory/'analyzer.mjs'),('after',REPO/'analyzers/typescript/analyzer.mjs')]:
            start=time.monotonic()
            command=['/usr/bin/time','-l','node','--max-old-space-size=192',str(REPO/'scripts/evaluation/node_probe_worker.mjs'),str(worker)]
            child=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=directory,
                                   env={k:v for k,v in os.environ.items()if k in {'PATH','HOME','LANG','LC_ALL'}},start_new_session=True)
            try:stdout,stderr=child.communicate(data,timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid,signal.SIGKILL);child.wait();raise ValueError('PROBE_TIMEOUT')
            if child.returncode or len(stdout)>2000000:raise ValueError('PROBE_WORKER_FAILED')
            result=json.loads(stdout);rss=re.search(rb'(\d+)\s+maximum resident set size',stderr)
            results.append(dict(projectId=project,sourceCommit=source_sha,stage=stage,version=result['analyzerVersion'],workerSha256=digest(worker.read_bytes()),inputSha256=digest(data),
                                wallMs=round((time.monotonic()-start)*1000),workerMaximumRssBytes=int(rss.group(1))if rss else None,
                                parsedFiles=sum(f['parseStatus']=='PARSED'for f in result['files']),entrypoints=sum(f['entrypoints']for f in result['files']),
                                functions=sum(f['functionsAnalyzed']for f in result['files']),findings=result['findings'],nodeUses=result.get('nodeUses'),
                                fileCoverage=result['files']))
    report=dict(schemaVersion=1,baselineMilestone=BASELINE,engineCommit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip(),
                projectId='OWASP--NodeGoat',sourceCommit=sha,heapLimitMiB=192,results=results,targetExecuted=False,
                limitations=['Same observed source is regression, not an independent accuracy estimate.','macOS maximum RSS includes native memory; single observations, not performance guarantees.','No target source packet or raw stderr persisted; API shape is not installed-library or runtime proof.'])
    write(output,report);print(dict(stages=len(results),sourceCommit=sha,targetExecuted=False))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root');p.add_argument('output');p.add_argument('--public-root');args=p.parse_args();probe(**vars(args))
