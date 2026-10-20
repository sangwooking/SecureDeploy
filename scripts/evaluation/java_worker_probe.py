"""macOS-only diagnostic of our trusted worker, using frozen selected text as data."""
import argparse
from pathlib import Path
import re
import shutil
import struct
import subprocess
import time
from application_track import read,write,outside,digest,relative

def packet(root,project,plan):
    source=root/'sources'/project['projectId']
    index={f['path']:f for p in plan['projects']if p['projectId']==project['projectId']for f in p.get('files',[])}
    names=[f['filePath']for f in project['runs'][0]['java']['analysis']['files']if f['parseStatus']=='NOT_RUN']
    if len(names)>100:raise ValueError('FILE_LIMIT')
    content={}
    for name in names:
        if not name.isascii():raise ValueError('ASCII_PATH_PROBE_ONLY')
        file=source/relative(name)
        if file.is_symlink()or not file.resolve().is_relative_to(source.resolve()):raise ValueError('SOURCE_PATH')
        data=file.read_bytes()
        if digest(data)!=index[name]['sha256']:raise ValueError('SOURCE_HASH')
        content[name]='\n'.join(data.decode().splitlines())
    if any(len(c)>100000 for c in content.values())or sum(map(len,content.values()))>1000000:raise ValueError('CHARACTER_LIMIT')
    names.sort(key=lambda name:(0 if any(h in content[name]for h in ['@RestController','@Controller','HttpServlet'])else 1,name))
    data=struct.pack('>i',len(names))
    for name in names:
        path=name.encode();text=content[name].encode()
        data+=struct.pack('>H',len(path))+path+struct.pack('>i',len(text))+text
    return data,content

def probe(root,jar,output):
    root=outside(root);jar=Path(jar).resolve();output=outside(output)
    raw=read(root/'raw-after-a.json');plan=read(root/'application-plan.json');results=[]
    if raw['planSha256']!=digest((root/'application-plan.json').read_bytes()):raise ValueError('PLAN_CHANGED')
    for project in raw['projects']:
        if not project.get('runs'):continue
        if not any(f['parseStatus']=='NOT_RUN'for f in project['runs'][0]['java']['analysis']['files']):continue
        data,content=packet(root,project,plan);start=time.monotonic()
        child=subprocess.run(['/usr/bin/time','-l',shutil.which('java'),'-Xmx192m','-Xss1m','-XX:MaxMetaspaceSize=96m','-XX:ActiveProcessorCount=1','-Xlog:gc*:stderr:uptime','-jar',str(jar)],
                             input=data,cwd='/private/tmp',env={'LANG':'en_US.UTF-8'},stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=12)
        # Never persist stderr, exception text, binary source packet or protocol bodies.
        error=child.stderr.decode(errors='replace')
        rss=re.search(r'(\d+)\s+maximum resident set size',error)
        heap=re.findall(r'\b(\d+)M->(\d+)M\((\d+)M\)',error)
        exit_heap=re.findall(r'(?:def new generation|tenured generation|garbage-first heap|ZHeap).*?total\s+(\d+)K,\s+used\s+(\d+)K',error)
        results.append(dict(projectId=project['projectId'],inputFiles=len(content),inputCharacters=sum(map(len,content.values())),inputSha256=digest(data),exitCode=child.returncode,
                            wallMs=round((time.monotonic()-start)*1000),workerMaximumRssBytes=int(rss.group(1))if rss else None,
                            observedGcHeapHighWaterMiB=max([int(v)for pair in heap for v in pair[:2]],default=None),
                            exitHeapUsedKiB=sum(int(v[1])for v in exit_heap)if exit_heap else None,
                            oomCategories=re.findall(r'OutOfMemoryError: (Java heap space|Metaspace|GC overhead limit exceeded|Compressed class space)',error),
                            protocolBytes=len(child.stdout),targetExecuted=False))
    if not results:raise ValueError('NO_FROZEN_FAILED_JAVA_SELECTION')
    write(output,dict(workerJarSha256=digest(jar.read_bytes()),heapLimitMiB=192,metaspaceLimitMiB=96,results=results,
                      limits='macOS time maximum RSS includes native memory; GC and exit-heap values are samples, not exact heap peaks. No target execution.'))
    return len(results)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root');p.add_argument('jar');p.add_argument('output');args=p.parse_args()
    try:print(dict(probedProjects=probe(**vars(args))))
    except Exception as error:print('Probe failed; category='+type(error).__name__);raise SystemExit(1)
