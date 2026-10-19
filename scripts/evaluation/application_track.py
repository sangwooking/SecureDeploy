"""Bounded whole-tree public application intake, isolated from CVE path truth.

Archives are read in memory, never executed or stored wholesale. Omitted files
and failed acquisitions are evidence, never clean security results.
"""
import argparse
from collections import Counter
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import urllib.request
import zlib
from benchmark import outside, read, write as write_metadata, digest, SECRET, relative, ID, LABELS
from cvefixes_metadata import NoRedirect

MAX_COMPRESSED=32_000_000
MAX_EXPANDED=128_000_000
MAX_FILE=4_000_000
MAX_FILES=20000
IGNORED={'node_modules','.git','build','dist','target','out','.gradle','coverage','vendor','.next','.venv','__pycache__'}
BINARY={'.png','.jpg','.jpeg','.gif','.ico','.webp','.avif','.woff','.woff2','.ttf','.otf','.pdf','.zip','.gz','.jar','.db','.sqlite3','.mp4','.svg'}
CREDENTIAL=re.compile(SECRET.pattern+rb'|AKIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{35}|xox[baprs]-[A-Za-z0-9-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----')


def write(path, data):
    if CREDENTIAL.search(json.dumps(data,ensure_ascii=False).encode()):
        raise ValueError('SENSITIVE_METADATA_PATTERN')
    write_metadata(path,data)


def unpack(data, destination, repository, sha):
    if len(data)>MAX_COMPRESSED:raise ValueError('ARCHIVE_COMPRESSED_LIMIT')
    stream=zlib.decompressobj(31)
    expanded=stream.decompress(data,MAX_EXPANDED+1)
    if len(expanded)>MAX_EXPANDED or stream.unconsumed_tail or not stream.eof or stream.unused_data:
        raise ValueError('ARCHIVE_EXPANSION_OR_STREAM_LIMIT')
    destination=outside(destination)
    destination.mkdir(mode=0o700)
    files=[];omitted=[];discovered=0;seen=set();root_name=repository.split('/')[1]+'-'+sha
    with tarfile.open(fileobj=io.BytesIO(expanded),mode='r:') as archive:
        for member in archive:
            if len(seen)>=MAX_FILES:raise ValueError('ARCHIVE_ENTRY_LIMIT')
            parts=PurePosixPath(member.name).parts
            if not parts or parts[0]!=root_name:raise ValueError('ARCHIVE_ROOT_IDENTITY')
            if len(parts)==1:continue
            name=str(relative('/'.join(parts[1:])))
            if name in seen:raise ValueError('ARCHIVE_DUPLICATE')
            seen.add(name)
            if member.isdir():continue
            discovered+=1
            reason=None
            if not member.isfile():reason='SYMLINK_HARDLINK_OR_SPECIAL_NOT_FOLLOWED'
            elif any(p in IGNORED for p in parts[1:-1]):reason='DIRECTORY_POLICY'
            elif member.size>MAX_FILE:reason='ACQUISITION_FILE_SIZE_LIMIT'
            elif Path(name).suffix.lower() in BINARY:reason='BINARY_ASSET_NOT_ANALYZED'
            if reason:
                omitted.append(dict(filePath=name,kind='FILE',fileType=None,status='LIMIT_EXCEEDED' if reason=='ACQUISITION_FILE_SIZE_LIMIT' else 'EXCLUDED',reason=reason));continue
            content=archive.extractfile(member).read(MAX_FILE+1)
            if len(content)!=member.size:raise ValueError('ARCHIVE_MEMBER_LENGTH')
            if CREDENTIAL.search(content):reason='CREDENTIAL_SHAPED_CONTENT_NOT_PERSISTED'
            else:
                try:content.decode('utf-8')
                except UnicodeDecodeError:reason='NON_UTF8_NOT_ANALYZED'
            if reason:
                omitted.append(dict(filePath=name,kind='FILE',fileType=None,status='EXCLUDED',reason=reason));continue
            path=destination/relative(name);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            with path.open('xb') as output:path.chmod(0o600);output.write(content)
            files.append(dict(path=name,sha256=digest(content),bytes=len(content)))
    licenses=[f for f in files if f['path'].lower() in {'license','license.txt','license.md','copying'}]
    if not licenses:raise ValueError('ROOT_LICENSE_NOT_ACQUIRED')
    return dict(discoveredArchiveFiles=discovered,retainedFiles=len(files),files=files,omitted=omitted,
                omissionCounts=dict(Counter(x['reason']for x in omitted)),licenseFiles=licenses,
                compressedBytes=len(data),expandedBytes=len(expanded),archiveSha256=digest(data))


def collect(selection, output):
    root=outside(output);root.mkdir(mode=0o700)
    (root/'sources').mkdir(mode=0o700)
    projects=[];total=0
    for candidate in selection['candidates']:
        if not candidate.get('selected'):continue
        repo=candidate['full_name'];sha=candidate['commitSha']
        if not re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repo)or not re.fullmatch('[0-9a-f]{40}',sha):raise ValueError('PINNED_PUBLIC_IDENTITY')
        project=dict(candidate);project['projectId']=repo.replace('/','--')
        project['groundTruth']='UNVERIFIED_PROJECT_NOT_SAFE_OR_VULNERABLE_LABEL'
        url=f'https://codeload.github.com/{repo}/tar.gz/{sha}'
        try:
            request=urllib.request.Request(url,headers={'User-Agent':'SecureDeploy-readonly-application-evaluation','Accept-Encoding':'identity'})
            with urllib.request.build_opener(NoRedirect()).open(request,timeout=30)as response:
                if response.status!=200:raise ValueError('ARCHIVE_HTTP_STATUS')
                if int(response.headers.get('Content-Length','0'))>MAX_COMPRESSED:raise ValueError('ARCHIVE_COMPRESSED_LIMIT')
                data=response.read(MAX_COMPRESSED+1)
            total+=len(data)
            if total>128_000_000:raise ValueError('BATCH_DOWNLOAD_LIMIT')
            project.update(unpack(data,root/'sources'/project['projectId'],repo,sha))
            project['collectionStatus']='COLLECTED_WITH_EXPLICIT_OMISSIONS' if project['omitted']else'COLLECTED'
            project['sourceUrl']=url
        except Exception as error:
            project['collectionStatus']='COLLECTION_FAILED';project['errorCategory']=type(error).__name__
            if isinstance(error,ValueError):project['failureReason']=str(error)
        projects.append(project)
        print(json.dumps(dict(project=repo,status=project['collectionStatus'],files=project.get('retainedFiles'),omissions=project.get('omissionCounts'))),flush=True)
    plan=dict(schemaVersion=1,track='REAL_WORLD_WEB_APPLICATION',projects=projects,selection=selection,
              inputSafety='Public archive static text only; no package install/build/import/PoV; no credentials used.',
              externalLookups='NOT_RUN',knownTruthPolicy='No whole-project SAFE label; findings and omissions need manual path review.',
              splits='Original family/project groups kept together; all observed cases become development material, not a future blind test.')
    write(root/'application-plan.json',plan)
    return plan


def run(root, output, project_id=None):
    import os,signal
    root=outside(root);output=outside(output)
    if output.exists():raise ValueError('NEW_OUTPUT_REQUIRED')
    env={k:v for k,v in os.environ.items()if k in {'PATH','HOME','LANG','LC_ALL','TMPDIR','JAVA_HOME'}}
    args=['gradle','--no-daemon','applicationEvaluation','-PapplicationRoot='+str(root),'-PapplicationOutput='+str(output)]
    if project_id:
        if not re.fullmatch('[A-Za-z0-9_.-]{1,150}',project_id):raise ValueError('PROJECT_ID')
        args.append('-PapplicationProjectId='+project_id)
    child=subprocess.Popen(args,cwd=Path(__file__).resolve().parents[2],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
    try:code=child.wait(timeout=900)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid,signal.SIGTERM)
        try:child.wait(timeout=3)
        except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait()
        raise ValueError('APPLICATION_EVALUATION_TIMEOUT')
    if code or not output.exists():raise ValueError('APPLICATION_EVALUATION_FAILED')
    return dict(status='OUTPUT_SAVED_NOT_A_SAFETY_VERDICT',output=str(output))


def summarize(root, raw_path, output, review):
    from benchmark import stable
    root=outside(root);raw=read(raw_path);plan=read(root/'application-plan.json')
    if raw['planSha256']!=digest((root/'application-plan.json').read_bytes()):raise ValueError('PLAN_CHANGED')
    if review['planSha256']!=raw['planSha256']or review['engineCommit']!=raw['engineCommit']:raise ValueError('REVIEW_VERSION')
    originals={p['projectId']:p for p in plan['projects']};summaries=[];index=[]
    ids=[p['projectId']for p in raw['projects']]
    if len(originals)!=len(plan['projects'])or len(ids)!=len(set(ids))or set(ids)!=set(originals):raise ValueError('RESULT_PROJECT_SET')
    if any(p.get('runs')and len(p['runs'])!=2 for p in raw['projects']):raise ValueError('RESULT_REPEAT_COUNT')
    output=outside(output);output.mkdir(mode=0o700)
    code_groups={};normalized={}
    for ident,p in originals.items():
        for f in p.get('files',[]):
            source=root/'sources'/ident/relative(f['path'])
            if source.is_symlink()or not source.resolve().is_relative_to(root/'sources'/ident)or digest(source.read_bytes())!=f['sha256']:
                raise ValueError('SOURCE_CHANGED_AFTER_EVALUATION')
            if Path(f['path']).suffix not in {'.java','.py','.js','.ts','.tsx','.jsx'}or f['bytes']<200:continue
            code_groups.setdefault(f['sha256'],set()).add(ident)
            data=(root/'sources'/ident/f['path']).read_bytes()
            normalized.setdefault(digest(re.sub(rb'\s+',b'',data)),set()).add(ident)
    for p in raw['projects']:
        original=originals[p['projectId']]
        summary={k:original.get(k)for k in ('projectId','repositoryUrl','commitSha','default_branch','license','evaluationSplit','collectionStatus','discoveredArchiveFiles','retainedFiles','omissionCounts','failureReason')}
        summary['evaluationStatus']=p['status'];summary['wholeProjectTruth']='UNVERIFIED'
        if p.get('runs'):
            r=p['runs'][0];c=r['coverage']
            summary['repeatConsistent']=stable(p['runs'][0])==stable(p['runs'][1])
            summary['coverage']={k:c[k]for k in ('status','discoveredFiles','selectedFiles','unsupportedFiles','excludedFiles','failedFiles','inventoryComplete','omittedEntries')}
            summary['ruleCounts']=dict(Counter(f['ruleId']for f in r['filtered']))
            summary['supplementalCounts']=dict(Counter(f['ruleId']for f in r['reviewCandidates']))
            summary['ruleSignals']=r['filtered'];summary['securityScore']=r['securityScore']
            summary['prioritySummary']=r['risk']['prioritySummary'];summary['deploymentAssessment']=r['risk']['prioritizedDeploymentAssessment']
            summary['riskPolicyVersion']=r['risk']['policyVersion'];summary['assessmentCoverage']=r['risk']['assessmentCoverage']
            summary['engineFingerprint']=r['engineFingerprint']
            summary['sca']=r['sca'];summary['elapsedMs']=[run['elapsedMs']for run in p['runs']]
            summary['sampledParentHeapBytes']=[run['parentHeapUsedBytes']for run in p['runs']]
            summary['analyzers']={}
            for lang in ('java','python','typescript'):
                worker=r[lang]['analysis']if lang=='java'else r[lang];files=worker.get('files',[])
                summary['analyzers'][lang]=dict(status=worker['status'],fileRecords=len(files),
                    parseStatuses=dict(Counter(f['parseStatus']for f in files)),entrypoints=sum(f.get('entrypoints',0)for f in files),
                    functions=sum(f.get('functionsAnalyzed',f.get('functions',0))for f in files),
                    sqlObservations=len(worker.get('sqlUses',worker.get('uses',[]))),httpObservations=len(worker.get('httpUses')or[]),
                    resourceObservations=len(worker.get('resourceUses')or[]),authorizationContexts=len(worker.get('authorizationContexts')or[]),
                    limitations=worker.get('limitations',[]))
                summary['analyzers'][lang]['analyzerVersion']=worker.get('analyzerVersion',worker.get('version'))
                summary['analyzers'][lang]['parserVersion']=worker.get('parserVersion')
        summaries.append(summary)
    # Path truth is independently scoped from unlabelled application totals.
    seen_reviews=set()
    for item in review['pathReviews']:
        if not ID.fullmatch(item['caseId'])or item['caseId']in seen_reviews or item['groundTruthLabel']not in LABELS:
            raise ValueError('REVIEW_ID_OR_TRUTH')
        seen_reviews.add(item['caseId'])
        p=originals[item['projectId']];file_index={f['path']:f for f in p.get('files',[])}
        refs=[]
        for site in item['sites']:
            f=file_index[site['filePath']];lines=(root/'sources'/p['projectId']/site['filePath']).read_text().splitlines()
            if site['line']<1 or site['line']>len(lines):raise ValueError('REVIEW_LOCATION')
            refs.append(dict(**site,sha256=f['sha256'],url=p['repositoryUrl']+'/blob/'+p['commitSha']+'/'+f['path']))
        pack=dict(item,publicReferences=refs,engineCommit=raw['engineCommit'],planSha256=raw['planSha256'],
                  repositoryUrl=p['repositoryUrl'],commitSha=p['commitSha'],license=item.get('fileLicense',p['license']),
                  reproduce='python3 -B scripts/evaluation/application_track.py run DATA_ROOT NEW_OUTPUT --project '+p['projectId'],
                  limits=['Static code/official teaching review only; no attack, target execution or runtime verification.',
                          'Whole project is unlabelled. Unsupported is not a confirmed FN; absence of finding is not TN.'])
        write(output/(item['caseId']+'.json'),pack)
        index.append({k:item.get(k)for k in ('caseId','projectId','groundTruthLabel','observed','cause','causeConfidence','improvementProposal')})
    result=dict(schemaVersion=1,track=raw['track'],engineCommit=raw['engineCommit'],planSha256=raw['planSha256'],projects=summaries,
                crossProjectExactCodeHashGroups=sum(len(x)>1 for x in code_groups.values()),
                crossProjectWhitespaceCloneGroups=sum(len(x)>1 for x in normalized.values()),
                duplicationLimit='Exact/whitespace checks only; semantic clones and unrecorded forks remain unverified.',
                externalLookups='NOT_RUN',riskMeaning='Actual Rule score and Risk policy with SCA UNKNOWN; not complete original-project deployment clearance.',
                metricsPolicy='Do not calculate whole-project TP/FN/recall without scoped ground truth.',
                measurementLimits='Timing excludes Gradle/Spring startup; heap is parent sample, not peak RSS or worker total.',
                reviews=index)
    write(output/'summary.json',result);write(output/'index.json',dict(packs=index))
    return dict(projects=len(summaries),packs=len(index),allCompletedRepeatsConsistent=all(p.get('repeatConsistent',True)for p in summaries))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('command',choices=['collect','run','summarize']);parser.add_argument('input');parser.add_argument('output');parser.add_argument('--project');parser.add_argument('--raw');parser.add_argument('--review');args=parser.parse_args()
    try:
        result=collect(read(args.input),args.output) if args.command=='collect'else summarize(args.input,args.raw,args.output,read(args.review))if args.command=='summarize'else run(args.input,args.output,args.project)
        print(json.dumps(dict(projectCount=len(result['projects']))if args.command=='collect'else result))
    except Exception as error:
        print('Application evaluation failed; category='+type(error).__name__)
        raise SystemExit(1)
