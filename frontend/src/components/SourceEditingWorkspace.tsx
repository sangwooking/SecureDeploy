import { indexWorkspaceFindings, severityOrder, type FileFinding } from './workspaceFindings';
import { DependencyFindingCard } from './DependencyFindingCard';
import { DependencyUpdatePlans } from './DependencyUpdatePlans';
import {confirmedSaveState,editedHash,saveLabels,type SaveState} from './saveConfirmation';
import {confirmEditingSave} from '../api/editingApi';
import {NpmTreePlanPanel} from './NpmTreePlanPanel';
import {originalVerified} from './sourceVerification';
import {loadSourceVerification,type SourceVerification} from '../api/editingApi';
import {OriginalSourceStatus} from './OriginalSourceStatus';
import {ProblemRepairGuide} from './ProblemRepairGuide';
import type {EditContext} from './problemGroups';
import {workspaceStorageKey} from './workspaceStorage';
import { workspaceRecoveryProblem, validResumedWorkspace } from './workspaceRecovery';
import { ApiRequestError, requestProblem } from '../api/requestProblem';
import { useUiCapabilities } from './useUiCapabilities';
import { WorkspaceDiffReview } from './WorkspaceOutcome';
import { WorkspaceAutomationPanels } from './WorkspaceAutomationPanels';
import { useEffect, useRef, useState, useMemo, memo } from 'react';
import { discoverEditingWorkspace, createEditingWorkspace, deleteEditingWorkspace, exportEditingWorkspace, loadEditingDiff, loadEditingFile, loadEditingWorkspace, saveEditingFile } from '../api/editingApi';
import type { EditingContent, EditingDiff, EditingFile, EditingWorkspace } from '../api/editingApi';
import type { SecurityReviewResponse } from '../types/securityReview';
import { AiPatchPanel } from './AiPatchPanel';
import { WorkspaceScanPanel } from './WorkspaceScanPanel';

interface TreeNode { name: string; children: Map<string, TreeNode>; file?: EditingFile }
const FileTree=memo(function FileTree({ files, selected, disabled, onSelect, index }: { files: EditingFile[]; selected?: string; disabled: boolean; onSelect: (file: EditingFile) => void; index: ReturnType<typeof indexWorkspaceFindings> }) {
  const root: TreeNode = { name: '', children: new Map() };
  for (const file of files) {
    let node = root;
    for (const name of file.path.split('/')) { if (!node.children.has(name)) node.children.set(name, { name, children: new Map() }); node = node.children.get(name)!; }
    node.file = file;
  }
  const render = (node: TreeNode): React.ReactNode => <ul>{[...node.children.values()].map(child => {
    const path=child.file?.path ?? '';
    const issues=index.byPath.get(path) ?? [];
    const severity=severityOrder[Math.max(0,...issues.map(item=>severityOrder.indexOf(item.severity)))];
    const status=index.inspected.has(path)?'원본 검사에서 연결된 문제 0건':'이 파일의 검사 여부 미확인';
    return <li key={child.name}>
    {child.children.size || child.file?.directory ? <details open><summary>{child.name}</summary>{render(child)}</details>
      : <button type="button" title={child.file?.path} disabled={disabled} aria-current={selected === child.file?.id ? 'true' : undefined}
          onClick={() => child.file && onSelect(child.file)}>
        <span className="workspace-file-name">{child.file?.changed ? '* ' : ''}{child.name}{!child.file?.editable ? ' (읽기 전용)' : ''}</span>
        {issues.length>0 ? <span className={`workspace-issue-count level-${severity.toLowerCase()}`} aria-label={`문제 ${issues.length}건, ${severity==='UNKNOWN'?'검토 필요':severity}`}>{issues.length}{severity==='UNKNOWN'?' · 검토':''}</span>
          : <span className="workspace-file-status" title={status}><span className="visually-hidden">{status}</span>{index.inspected.has(path)?'0':'—'}</span>}
      </button>}
  </li>;})}</ul>;
  return render(root);
});

export function SourceEditingWorkspace({ result, onBack, initialPath, initialAdviceId, problemContext, invalidProblem=false, embedded=false }: { result: SecurityReviewResponse; onBack: () => void; initialPath?: string; initialAdviceId?: string;problemContext?:EditContext;invalidProblem?:boolean;embedded?:boolean }) {
  const cap=useUiCapabilities();
  const key = workspaceStorageKey(result.reviewId);
  const legacyKey=`securedeploy.editing.${result.reviewId}`;
  const [workspace, setWorkspace] = useState<EditingWorkspace | null>(null);
  const [selected, setSelected] = useState<EditingFile | null>(null);
  const [content, setContent] = useState<EditingContent | null>(null);
  const [text, setText] = useState('');
  const textRef=useRef(text);textRef.current=text;
  const [zip, setZip] = useState<File | null>(null);
  const [sourceRecord,setSourceRecord]=useState<{id:number;value:SourceVerification}|null>(null);
  const [sourceConsent,setSourceConsent]=useState(false);
  const [sourceFailure,setSourceFailure]=useState<SourceVerification>();
  useEffect(()=>{let current=true;setSourceConsent(false);setSourceFailure(undefined);if(result.reviewId)loadSourceVerification(result.reviewId).then(value=>{if(current)setSourceRecord({id:result.reviewId!,value});}).catch(()=>{});return()=>{current=false;};},[result.reviewId]);
  const retention=sourceRecord&&sourceRecord.id===result.reviewId?sourceRecord.value.retention:undefined;
  const [busy, setBusy] = useState(false), [error, setError] = useState('');
  const [diffs, setDiffs] = useState<EditingDiff[] | null>(null), [approved, setApproved] = useState(false);
  const [expired, setExpired] = useState(false);
  const [remainingMinutes,setRemainingMinutes]=useState<number|null>(null);
  const [resumeId,setResumeId]=useState('');
  const [discovery,setDiscovery]=useState<import('../api/editingApi').WorkspaceDiscovery|null>(null);
  const [revisionConflict,setRevisionConflict]=useState(false);
  const [resumeAttempt,setResumeAttempt]=useState(0);
  const [recovery,setRecovery]=useState<ReturnType<typeof workspaceRecoveryProblem>|null>(null);
  const [saveState,setSaveState]=useState<SaveState|null>(null);
  const [pendingSave,setPendingSave]=useState<{workspaceId:string;fileId:string;baseRevision:number;expectedHash:string;requestId:string;text:string}|null>(null);
  const [stage, setStage] = useState<'edit'|'diff'|'scan'>('edit');
  const [pane, setPane] = useState<'files'|'code'|'evidence'>('files');
  const [evidenceOpen, setEvidenceOpen] = useState(!!problemContext);
  const [fileQuery, setFileQuery] = useState('');
  const [showLocations,setShowLocations]=useState(false);
  const [locationPage,setLocationPage]=useState(0);
  const [onlyIssues,setOnlyIssues]=useState(false);
  const [activeId,setActiveId]=useState<string>();
  const [lineTarget,setLineTarget]=useState(0);
  const restoredIssue=useRef<string|undefined>(undefined);
  const [allFiles,setAllFiles]=useState(true);
  const dirty = content !== null && text !== content.text.replace(/\r\n/g, '\n');
  const [rescanned,setRescanned]=useState<SecurityReviewResponse>();
  const latest=rescanned?.workspaceScan?.workspaceId===workspace?.id&&rescanned?.workspaceScan?.revision===workspace?.revision&&!dirty?rescanned:undefined;
  const workspaceFiles=workspace?.files;
  const index=useMemo(()=>indexWorkspaceFindings(result,new Set(workspaceFiles?.filter(f=>!f.directory).map(f=>f.path))),[result,workspaceFiles]);
  const treeIndex=useMemo(()=>latest?indexWorkspaceFindings(latest,new Set(workspaceFiles?.filter(f=>!f.directory).map(f=>f.path))):index,[latest,workspaceFiles,index]);
  const issues=selected?index.byPath.get(selected.path)??[]:[];
  const issue=issues.find(item=>item.id===activeId);
  const selectionKey=workspace?`${key}.${workspace.id}.file-selection`:undefined;
  const pendingLine=useRef<number|undefined>(undefined);
  const targetPath=problemContext?.path??initialPath;
  const isDependencyContext=!!problemContext&&!!result.riskAssessment?.dependencyFindings?.some(f=>f.findingId===problemContext.findingId);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    let current=true;
    const stored = sessionStorage.getItem(key)??sessionStorage.getItem(legacyKey);
    setResumeId(stored??''); setRecovery(null);
    if (stored) {
      setBusy(true);
      loadEditingWorkspace(stored).then(value => {
        if (!validResumedWorkspace(value,stored,result.reviewId)) throw new Error('WORKSPACE_REVIEW_MISMATCH');
        if(current){sessionStorage.setItem(key,value.id);setWorkspace(value);setExpired(Date.parse(value.expiresAt)<=Date.now());}
      }).catch(e => { if(current)setRecovery(workspaceRecoveryProblem(e)); })
        .finally(() => { if(current)setBusy(false); });
    } else if(result.reviewId) {
      setBusy(true);discoverEditingWorkspace(result.reviewId).then(value=>{if(current)setDiscovery(value);}).catch(()=>{if(current)setDiscovery(null);}).finally(()=>{if(current)setBusy(false);});
    }
    return () => { current=false;mounted.current = false; };
  }, [key,resumeAttempt]);
  useEffect(() => {
    const check = () => { if(workspace)setRemainingMinutes(Math.max(0,Math.ceil((Date.parse(workspace.expiresAt)-Date.now())/60000))); if (workspace && Date.parse(workspace.expiresAt) <= Date.now()) { setExpired(true);setSaveState('EXPIRED'); setDiffs(null); setApproved(false); } };
    check(); const timer = setInterval(check, 1000); return () => clearInterval(timer);
  }, [workspace]);
  useEffect(() => {
    const leave = (event: BeforeUnloadEvent) => { if (dirty) { event.preventDefault(); event.returnValue = ''; } };
    window.addEventListener('beforeunload', leave); return () => window.removeEventListener('beforeunload', leave);
  }, [dirty]);
  useEffect(()=>{
    const leave=(event:Event)=>{if(dirty&&!window.confirm('저장하지 않은 편집을 버리고 이동할까요?'))event.preventDefault();};
    window.addEventListener('securedeploy:before-navigate',leave);return()=>window.removeEventListener('securedeploy:before-navigate',leave);
  },[dirty]);
  const run = async (action: () => Promise<void>) => {
    if (busy) return;
    setBusy(true); setError('');
    try { await action(); } catch (e) { if(!workspace&&e instanceof ApiRequestError&&(e.code==='SOURCE_MISMATCH'||e.code==='SOURCE_UNAVAILABLE'||[403,404,502,503].includes(e.status)))setSourceFailure({status:e.code==='SOURCE_MISMATCH'?'MISMATCH':'UNAVAILABLE',message:e.message,scope:'ORIGINAL_BYTES_ONLY',recorded:!!sourceRecord?.value.recorded,fileCount:sourceRecord?.value.fileCount??0}); if(e instanceof ApiRequestError&&e.code==='WORKSPACE_REVISION_CONFLICT')setRevisionConflict(true);
      if(result.reviewId&&e instanceof ApiRequestError&&e.code==='WORKSPACE_ALREADY_OPEN')discoverEditingWorkspace(result.reviewId).then(setDiscovery).catch(()=>{});
      if (mounted.current) setError(e instanceof ApiRequestError?requestProblem(e,'수정 작업').message:e instanceof TypeError?'서버에 연결하지 못했어요. 네트워크를 확인해 주세요.':e instanceof Error?e.message:'요청을 완료하지 못했습니다.'); }
    finally { if (mounted.current) setBusy(false); }
  };
  const resumeDiscovered=()=>void run(async()=>{
    const known=discovery?.workspace;if(!known)return;
    const value=await loadEditingWorkspace(known.id);
    if(!validResumedWorkspace(value,known.id,result.reviewId))throw new Error('WORKSPACE_REVIEW_MISMATCH');
    if(dirty)return;
    sessionStorage.setItem(key,value.id);setResumeId(value.id);setWorkspace(value);setDiscovery(null);setRecovery(null);setExpired(Date.parse(value.expiresAt)<=Date.now());
  });
  const exportDraft=()=>{
    if(!content||!selected)return;
    const blob=new Blob([text],{type:'text/plain;charset=utf-8'}),url=URL.createObjectURL(blob),link=document.createElement('a');
    link.href=url;link.download=`securedeploy-unsaved-${selected.path.split('/').pop()}.txt`;document.body.appendChild(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
  };
  const refreshSaved=()=>void run(async()=>{
    if(!workspace||dirty&&!window.confirm('현재 편집을 내보냈나요? 최신 저장본을 불러오면 이 탭의 미저장 편집을 버립니다.'))return;
    const next=await loadEditingWorkspace(workspace.id);
    const value=selected?await loadEditingFile(next.id,selected.id):null;
    if(value&&value.revision!==next.revision)throw new Error('다른 탭이 다시 저장했어요. 현재 편집은 유지됩니다. 다시 확인해 주세요.');
    setWorkspace(next);setContent(value);setText(value?.text.replace(/\r\n/g,'\n')??'');setDiffs(null);setApproved(false);setRevisionConflict(false);
  });
  const start = () => run(async () => {
    setSourceFailure(undefined);
    if (!result.reviewId) return;
    if(dirty&&!window.confirm('새 작업은 이전 편집을 복원하지 않습니다. 현재 편집 내용을 복사했으며 새 작업을 시작할까요?'))return;
    const value = await createEditingWorkspace(result.reviewId, result.sourceType === 'ZIP' ? zip ?? undefined : undefined);
    if (mounted.current) { setWorkspace(value); setDiscovery(null); setRevisionConflict(false); setRecovery(null); setResumeId(value.id); setExpired(false); setSelected(null); setContent(null); setText(''); setDiffs(null); setApproved(false); setFileQuery(''); sessionStorage.setItem(key, value.id); }
  });
  const select = (file: EditingFile,line?:number) => void run(async () => {
    if (dirty && !window.confirm('저장하지 않은 편집을 버리고 다른 파일을 열까요?')) return;
    setSaveState(null);setPendingSave(null);setDiffs(null); setApproved(false); setSelected(file); setContent(null); setText('');
    const items=index.byPath.get(file.path)??[];
    const initial=items.find(i=>i.flow?.findingId===problemContext?.flow?.findingId && i.flow && problemContext?.flow
      || i.code?.vulnerabilityId!=null&&i.code.vulnerabilityId===problemContext?.vulnerability?.vulnerabilityId
      || i.dependency?.osvId&&i.dependency.osvId===result.riskAssessment?.dependencyFindings?.find(r=>r.findingId===problemContext?.findingId)?.advisoryId);
    const restored=items.find(i=>i.id===restoredIssue.current);
    restoredIssue.current=undefined;
    setActiveId(initial?.id??restored?.id);
    pendingLine.current=line??initial?.line??restored?.line??(items.length===1?items[0].line:undefined);setPane('code');
    if (workspace && !expired && file.editable) {
      const value = await loadEditingFile(workspace.id, file.id);
      if (value.revision !== workspace.revision) throw new Error('다른 탭에서 변경되었습니다. 작업 공간을 새로고침해 주세요.');
      setContent(value); setText(value.text.replace(/\r\n/g, '\n'));
    }
  });
  useEffect(()=>{
    if(workspace&&!expired&&!selected&&!busy){
      const stored=selectionKey?sessionStorage.getItem(selectionKey):null;
      restoredIssue.current=selectionKey?sessionStorage.getItem(selectionKey+'.finding')??undefined:undefined;
      const file=workspace.files.find(f=>!f.directory&&f.path===(targetPath??stored));
      if(file)select(file,problemContext?.line);
    }
  },[workspace?.id,targetPath,busy,selected?.id]);
  useEffect(()=>{if(selectionKey&&selected)sessionStorage.setItem(selectionKey,selected.path);if(selectionKey&&selected)sessionStorage.setItem(selectionKey+'.finding',activeId??'');},[selectionKey,selected?.path,activeId]);
  const pickIssue=(item:FileFinding)=>{
    setActiveId(item.id);
    setEvidenceOpen(true);
    pendingLine.current=dirty?undefined:item.line;
    setLineTarget(n=>n+1);
  };
  useEffect(()=>{
    const line=pendingLine.current;
    pendingLine.current=undefined;if(!line||!content||content.currentHash!==content.originalHash||!originalVerified(workspace))return;
    const lines=content.text.replace(/\r\n/g,'\n').split('\n');if(line<1||line>lines.length)return;
    const editor=document.getElementById('source-code') as HTMLTextAreaElement|null;if(!editor)return;
    const start=lines.slice(0,line-1).reduce((n,s)=>n+s.length+1,0);editor.setSelectionRange(start,start+lines[line-1].length);editor.scrollTop=Math.max(0,(line-3)*22);if(pane==='code')editor.focus({preventScroll:true});
  },[content,workspace?.identityStatus,lineTarget]);
  const verifySave = async (pending:NonNullable<typeof pendingSave>) => {
    setSaveState('CHECKING');
    try {
      const status=await confirmEditingSave(pending.workspaceId,pending);if(!mounted.current)return;
      const state=confirmedSaveState(status);setSaveState(state);
      if(state==='EXPIRED'){setExpired(true);setApproved(false);setDiffs(null);return;}
      if(state==='CONFLICT'){setRevisionConflict(true);return;}
      if(state!=='CONFIRMED'){if(state==='NOT_SAVED')setPendingSave(null);return;}
      const next=await loadEditingWorkspace(pending.workspaceId),value=await loadEditingFile(pending.workspaceId,pending.fileId);
      if(next.revision!==status.revision||value.revision!==next.revision||value.currentHash!==pending.expectedHash){setSaveState('CONFLICT');setRevisionConflict(true);return;}
      if(Date.parse(next.expiresAt)<=Date.now()){setExpired(true);setSaveState('EXPIRED');return;}
      setWorkspace(next);setSelected(next.files.find(f=>f.id===pending.fileId)??null);setContent(value);
      // A new browser edit made during reconnection is never discarded.
      setText(current=>current===pending.text?value.text.replace(/\r\n/g,'\n'):current);
      setSaveState(textRef.current===pending.text?'CONFIRMED':null);setDiffs(null);setApproved(false);setRevisionConflict(false);setPendingSave(null);
    }catch(e){if(!mounted.current)return;setSaveState('UNKNOWN');if(e instanceof ApiRequestError&&e.status===403)setError('접근 권한을 확인할 수 없습니다. 현재 편집을 보관해 주세요.');}
  };
  const save = (revert: boolean) => void run(async () => {
    if (!workspace || !selected || !content || expired) return;
    if(pendingSave){await verifySave(pendingSave);return;}
    if (revert && !window.confirm('이 파일의 변경을 모두 취소하고 불변 원본으로 되돌릴까요?')) return;
    const pending={workspaceId:workspace.id,fileId:selected.id,baseRevision:workspace.revision,expectedHash:revert?selected.originalHash:await editedHash(text,content),requestId:crypto.randomUUID(),text};
    setPendingSave(pending);setSaveState('CHECKING');
    try {await saveEditingFile(workspace,selected,text,revert,pending.requestId);}
    catch(e){if(e instanceof ApiRequestError&&e.code==='WORKSPACE_EXPIRED'){setSaveState('EXPIRED');setExpired(true);setApproved(false);setDiffs(null);return;}}
    // One read-only verification; no automatic write replay, even after response loss.
    await verifySave(pending);
  });
  const reviewDiff = () => void run(async () => {
    if (!workspace || dirty || expired) return;
    const values: EditingDiff[] = [];
    for (const id of workspace.changedFileIds) {
      const value = await loadEditingDiff(workspace.id, id);
      if (value.revision !== workspace.revision) throw new Error('변경 revision이 다릅니다. 다시 불러와 주세요.');
      values.push(value);
    }
    setDiffs(values); setApproved(false);
  });
  const download = (format: 'zip' | 'patch') => void run(async () => {
    if (!workspace || !approved || diffs === null || dirty || expired) return;
    const blob = await exportEditingWorkspace(workspace, format);
    const url = URL.createObjectURL(blob), link = document.createElement('a');
    link.href = url; link.download = `securedeploy-edited-r${workspace.revision}.${format}`;
    document.body.appendChild(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    setApproved(false);
  });
  const clear = () => void run(async () => {
    if (workspace && !window.confirm('원본과 편집 내용을 삭제하고 작업 공간을 닫을까요? 복구할 수 없습니다.')) return;
    if (workspace && !expired) await deleteEditingWorkspace(workspace.id);
    sessionStorage.removeItem(key); setResumeId(''); setRecovery(null); setWorkspace(null); setContent(null); setSelected(null); setText(''); setDiffs(null); setApproved(false); setExpired(false); setFileQuery('');
  });
  const visibleFiles=useMemo(()=>workspace?.files.filter(f=>(!onlyIssues||treeIndex.byPath.has(f.path))&&f.path.toLowerCase().includes(fileQuery.trim().toLowerCase()))??[],[workspace,fileQuery,onlyIssues,treeIndex]);
  const findings = selected && originalVerified(workspace)
    ? result.vulnerabilities.filter(v => v.filePath.replace(/\\/g, '/') === selected.path) : [];
  const flowFindings = selected && originalVerified(workspace)
    ? [...(result.serverAnalysis?.validatedFindings ?? []), ...(result.serverAnalysis?.pythonAnalysis?.validatedFindings ?? [])]
      .filter(f => f.location.filePath.replace(/\\/g, '/') === selected.path) : [];
  if(cap.value?.recoveryReadOnly)return <section aria-label="수정 작업 공간"><p role="status">읽기 전용 복구 모드에서는 수정 작업을 재개할 수 없습니다. 저장된 작업은 삭제되지 않으며 정상 모드로 복귀한 뒤 다시 열 수 있습니다.</p></section>;
  return <section className={`source-editor stage-${stage} pane-${pane} ${evidenceOpen?'evidence-open':''}`} aria-label="수정 작업 공간">
    <header className="source-editor-header"><div><h2>수정 작업 공간</h2><p>{result.projectName} · 검사 #{result.reviewId}</p></div>
      {!embedded&&<button type="button" className="secondary-button" aria-label="분석 결과로 돌아가기" disabled={busy} onClick={() => { if (!dirty || window.confirm('저장하지 않은 편집을 버리고 결과로 돌아갈까요?')) onBack(); }}>결과로 돌아가기</button>}</header>
    {invalidProblem&&<p role="alert">선택한 문제가 이 검사에 없습니다. 위치를 추정하지 않으며 보안 결과에서 다시 선택해 주세요.</p>}
    {sourceFailure?<OriginalSourceStatus value={sourceFailure}/>:workspace?<OriginalSourceStatus value={workspace.sourceVerification}/>:<OriginalSourceStatus reviewId={result.reviewId}/>}
    {problemContext&&<section className="editing-problem-context" aria-label="현재 수정 중인 문제"><h3>현재 수정 중: {problemContext.title}</h3><p><code>{problemContext.path}</code>{problemContext.line?` · 원본 ${problemContext.line}행`:''}</p><details><summary>선택한 문제 식별 정보</summary><p>검사 #{result.reviewId} · {problemContext.findingId} · {problemContext.ruleId}</p></details>
      {workspace&&<><p>{originalVerified(workspace)?'원본 바이트·해시 연결 확인':'원본 동일성 미확인 · 과거 행 위치 확정 연결 안 함'} · 수정본 r{workspace.revision}</p><details onToggle={e=>setShowLocations(e.currentTarget.open)}><summary>원본 해시·수정 위치 ({problemContext.locations.length}곳)</summary><p>{workspace.sourceRevision}</p>{showLocations&&problemContext.locations.slice(locationPage*50,locationPage*50+50).map(l=>{const f=workspace.files.find(f=>f.path===l.path);return <div key={l.findingId}><button type="button" disabled={busy||expired||!f} onClick={()=>f&&select(f,l.line)}>문제 위치 보기 · {l.path}{l.line?` · ${l.line}행`:''}</button>{f&&<code>{f.originalHash}</code>}</div>})}{showLocations&&problemContext.locations.length>50&&<nav aria-label="작업 문제 위치 페이지"><button disabled={locationPage===0} onClick={()=>setLocationPage(n=>n-1)}>이전 위치</button><span>{locationPage+1} / {Math.ceil(problemContext.locations.length/50)}</span><button disabled={(locationPage+1)*50>=problemContext.locations.length} onClick={()=>setLocationPage(n=>n+1)}>다음 위치</button></nav>}</details></>}
      <button type="button" onClick={()=>{setEvidenceOpen(true);setPane('evidence');requestAnimationFrame(()=>document.getElementById('workspace-problem-guide')?.scrollIntoView({block:'nearest'}));}}>수정 가이드 보기</button></section>}
    {recovery && <div role="alert" className="workspace-recovery"><p><strong>{recovery.message}</strong></p><p>이 안내만으로 만료나 데이터 손실을 확정할 수 없습니다. 이전 작업 식별자는 재시도를 위해 유지합니다.</p><button type="button" disabled={busy} onClick={()=>setResumeAttempt(n=>n+1)}>이전 작업 다시 확인</button></div>}
    {saveState&&<div role="status" aria-label="저장 결과"><strong>{saveLabels[saveState]}</strong>{saveState==='CONFIRMED'?<p>영속 Workspace의 파일 해시와 최신 버전을 확인했습니다. 재검사·다운로드 승인은 별도입니다.</p>:<p>현재 편집을 유지합니다. 응답이 없었다는 이유만으로 저장 실패를 확정하지 않으며, 자동으로 다시 저장하지 않습니다.</p>}{pendingSave&&saveState!=='CHECKING'&&<button type="button" disabled={busy} onClick={()=>void run(()=>verifySave(pendingSave))}>저장 결과 다시 확인</button>}</div>}
    {error && <p className="error-message" role="alert">{error}</p>}
    {content&&(dirty||expired)&&<div role="note"><p>이 탭에 남은 현재 편집을 텍스트로 내보낼 수 있습니다. 미저장 편집은 다른 탭·서버에 보관되지 않습니다. 새로고침·계정 변경 전에 내보내 주세요.</p><button type="button" onClick={exportDraft}>현재 편집 텍스트 내보내기</button></div>}
    {revisionConflict&&<div role="alert"><p>이 탭의 편집은 유지했습니다. 다른 탭의 변경을 덮어쓰지 않았습니다.</p><button type="button" disabled={busy} onClick={refreshSaved}>편집 내보내기 후 최신 저장본 확인</button></div>}
    {!workspace ? <div className="source-editor-acquire">
      {discovery?.state==='AVAILABLE'&&<div role="status"><p>진행 중인 수정 작업이 있어요.</p><p>서버에 저장된 내용만 이어집니다. 다른 탭의 미저장 편집은 가져오지 않습니다. 이용 시간은 연장되지 않습니다.</p><button type="button" className="primary-button" disabled={busy} onClick={resumeDiscovered}>기존 작업 이어서 하기</button></div>}
      {discovery?.state==='OTHER_REVIEW'&&<p role="status">다른 검사에서 진행 중인 수정 작업이 있어요. 해당 작업을 내보내고 명시적으로 닫은 뒤 새 작업을 시작해 주세요.</p>}
      {discovery?.state==='CREATING'&&<p role="status">다른 탭에서 원본을 확보하고 있어요. 잠시 후 이 화면을 다시 확인해 주세요.</p>}
      <p>보관 방식과 만료 시각은 원본 확보 후 표시됩니다. 미저장 편집은 복구되지 않습니다. 편집 내용은 자동 재검사되거나 GitHub에 반영되지 않으며, 다른 탭에서 계정을 변경하기 전에 필요한 Patch/ZIP을 내보내 주세요.</p>
      {result.sourceType === 'ZIP' ? <><p role="note">검사 당시 업로드한 ZIP을 선택하세요. 저장된 ZIP·파일 해시와 비교하며, 기록이 없는 과거 검사는 동일성을 확정하지 않습니다.</p>
        <label>원본 ZIP <input type="file" accept=".zip,application/zip" disabled={busy} onChange={e => setZip(e.target.files?.[0] ?? null)} /></label></>
        : <p>현재 읽기 권한을 확인하고 분석 당시 commit만 가져옵니다. 해당 commit을 확보하지 못하면 작업을 중단합니다.</p>}
      {result.sourceType === 'WORKSPACE' && <p role="note">수정본 Review에는 전체 소스를 보관하지 않습니다. 기존 작업 공간을 이용하거나 다운로드한 ZIP으로 새 분석을 시작해 주세요.</p>}
      {retention&&<label><input type="checkbox" checked={sourceConsent} disabled={busy} onChange={e=>setSourceConsent(e.target.checked)}/>{retention.storageMode==='ENCRYPTED_PERSISTENT'?'암호화된 서버':'서버 메모리'}에 원본과 저장한 수정 내용을 {Math.floor(retention.seconds/60)}분 동안 보관하는 데 동의합니다. 최대 {retention.maxFiles}개 항목·{Math.floor(retention.maxBytes/1024/1024)}MiB이며, 미저장 편집은 보관되지 않습니다.</label>}
      <button className="primary-button" type="button" disabled={busy || !retention || !sourceConsent || (!!discovery&&discovery.state!=='NONE') || (!!resumeId && recovery?.allowSourceAttempt!==true) || !result.reviewId || !result.sourceType || result.sourceType === 'WORKSPACE' || (result.sourceType === 'ZIP' && !zip)} onClick={() => void start()}>{busy ? '원본 확인 중...' : '원본 확보 시도 후 새 작업 시작'}</button>
    </div> : <>
      <div className="source-editor-status"><p><strong>수정본 버전 {workspace.revision}</strong> · 만료 {new Date(workspace.expiresAt).toLocaleString('ko-KR')} · 변경 {workspace.changedFileIds.length}개</p><p>생성 시각부터 보존하며 저장·재접속으로 만료 시각이 연장되지 않습니다. 재검사 기록은 별도이고, Workspace의 상세 다운로드 승인 내역은 만료까지만 보관됩니다. 감사 이벤트가 활성화된 서버에서는 별도 보존 정책이 적용됩니다. 이미 내려받은 파일은 사용자 보관 자료입니다.</p>
        <p role="note">{workspace.storageMode==='ENCRYPTED_PERSISTENT'
          ? '암호화된 서버 저장 작업입니다. 저장한 파일·수정 출처·다운로드 승인 이력은 만료 전까지 서버 재시작 후 이어갈 수 있습니다. 미저장 편집과 검토 중인 제안은 복구되지 않습니다.'
          : '임시 작업 공간입니다. 저장한 파일과 AI 제안도 30분 또는 서버 재시작 시 사라집니다. 보관하려면 변경 검토·승인 후 Patch/ZIP을 내보내 주세요.'}</p>
        <details><summary>원본·해시 정보</summary><p className="source-revision">원본: {workspace.sourceRevision}</p></details>
        {workspace.identityStatus === 'UNVERIFIED_REUPLOAD' && <p role="note">이전 검사 원본과 같은 파일인지 확인하지 못했어요. 과거 문제 위치를 연결하지 않으며, 수정 후 새 검사가 필요해요.</p>}
        {remainingMinutes!==null&&remainingMinutes>0&&remainingMinutes<=5&&<p role="alert">작업 공간 이용 시간이 {remainingMinutes}분 이내로 남았어요. 서버에 저장한 변경은 기한 전에 검토·승인 후 Patch/ZIP으로 내보내세요. 이 탭의 미저장 변경은 별도로 텍스트를 내보내세요. 저장으로 기한이 연장되지 않습니다. 자동 다운로드하지 않습니다.</p>}
        {expired && <div role="alert"><p>이전 수정 작업을 이어갈 수 없어요. 작업 공간의 이용 시간이 지났습니다.</p><p>새 작업은 이전 변경을 복원하지 않습니다. 아래 편집 내용이 남아 있다면 먼저 복사해 보관해 주세요.</p>{result.sourceType==='GITHUB'&&result.sourceMetadata?.commitSha&&<><p>분석 당시 원본을 실제로 확보한 경우에만 새 작업을 시작합니다.</p><button type="button" className="primary-button" disabled={busy} onClick={()=>void start()}>원본 확보 가능 여부 확인</button></>}{content&&<label>브라우저에 남은 편집 내용<textarea aria-label="만료된 작업의 편집 내용" className="source-code" readOnly value={text}/></label>}</div>}
        <details><summary>작업 공간 관리</summary><button type="button" className="secondary-button" disabled={busy} onClick={clear}>작업 공간 삭제</button></details>
      </div>
      <nav className="editing-stages" aria-label="수정 단계">{([['edit','코드 수정'],['diff','변경 검토·승인'],['scan','재검사']] as const).map(([id,label],index)=><button key={id} type="button" aria-current={stage===id?'step':undefined} onClick={()=>setStage(id)}><span className="stage-number" aria-hidden="true">{index+1}</span>{label}</button>)}</nav>
      {initialAdviceId&&!cap.loading&&(!cap.value?.dependencyFiles||!cap.value.npmGeneration)&&<p role="note">이 서버에서는 npm 수정 파일 생성이 준비되지 않았어요. 파일을 직접 수정하고 Diff를 검토할 수 있습니다.</p>}
      {stage==='edit'&&isDependencyContext&&cap.value?.npmIsolation&&cap.value.npmIsolation.state!=='AVAILABLE_OFFLINE_BROKER'&&<p role="note">{cap.value.npmIsolation.message}</p>}
      {stage==='edit'&&cap.value?.npmTreePlans&&!!result.sca?.dependencyVulnerabilities?.some(d=>d.ecosystem==='NPM')&&!initialAdviceId&&<NpmTreePlanPanel workspace={workspace} result={result} findingId={problemContext?.findingId} disabled={busy||dirty||expired} onApplied={async next=>{setWorkspace(next);setDiffs(null);setApproved(false);if(selected){const value=await loadEditingFile(next.id,selected.id);setContent(value);setText(value.text.replace(/\r\n/g,'\n'));}setStage('diff');}}/>}
      {stage==='edit'&&initialAdviceId&&cap.value?.dependencyFiles&&cap.value.npmGeneration&&<WorkspaceAutomationPanels workspace={workspace} adviceId={initialAdviceId} disabled={busy||dirty||expired} onApplied={async next=>{setWorkspace(next);setDiffs(null);setApproved(false);if(selected){const value=await loadEditingFile(next.id,selected.id);setContent(value);setText(value.text.replace(/\r\n/g,'\n'));}}}/>}
      <div hidden={stage!=='scan'}>{workspace.changedFileIds.length===0&&<p>수정한 파일을 저장한 뒤 재검사할 수 있어요.</p>}<div hidden={workspace.changedFileIds.length===0}><WorkspaceScanPanel workspace={workspace} original={result} onResult={setRescanned} disabled={busy || dirty || expired || workspace.changedFileIds.length===0} /></div></div>
      {!expired && <>
        <div hidden={stage!=='edit'}>
        <nav className="editing-panes" aria-label="편집 화면">{([['files','파일'],['code','코드'],['evidence','수정 근거']] as const).map(([id,label])=><button key={id} type="button" aria-pressed={pane===id} onClick={()=>{setPane(id);if(id==='evidence')setEvidenceOpen(true);}}>{label}</button>)}</nav>
        <div className="editor-toolbar"><span>{selected?.path ?? '파일 선택'}</span><button type="button" className="secondary-button" aria-expanded={evidenceOpen} onClick={()=>setEvidenceOpen(!evidenceOpen)}>{evidenceOpen?'수정 근거 접기':'수정 근거 열기'}</button></div>
        <div className="source-editor-layout">
          <nav className="source-file-tree" aria-label="프로젝트 파일">
            <label className="file-search">파일 찾기<input type="search" value={fileQuery} onChange={e=>setFileQuery(e.target.value)} placeholder="파일명 또는 경로" /></label>
            {problemContext&&workspace&&<div aria-label="현재 문제 관련 파일">{new Set(problemContext.locations.map(l=>l.path)).size>50&&<p>관련 파일 50개를 우선 표시합니다. 전체 파일 검색 또는 문제 위치 페이지에서 다른 위치를 선택하세요.</p>}{[...new Set(problemContext.locations.map(l=>l.path))].slice(0,50).map(path=>{const f=workspace.files.find(f=>f.path===path);return f?<button key={f.id} type="button" disabled={busy} aria-current={selected?.id===f.id?'true':undefined} onClick={()=>select(f)}>{path}</button>:<p key={path}>원본에서 파일을 찾지 못했습니다: {path}</p>})}</div>}
            <label>표시할 파일 <select value={onlyIssues?'issues':'all'} onChange={e=>{setOnlyIssues(e.target.value==='issues');setAllFiles(true);}}><option value="all">전체 파일</option><option value="issues">문제가 있는 파일</option></select></label>
            <p className="workspace-finding-basis">검사 #{latest?.reviewId??result.reviewId} · 범위 {(latest??result).coverage?.status??'UNKNOWN'}{latest?' · 현재 저장본 재검사':workspace.changedFileIds.length>0||dirty?' · 수정 후 재검사 전':''}<br/>배지는 대표 위치 기준입니다. 0은 검사 범위에서 연결된 문제 없음, —는 검사 여부 미확인입니다.</p>
            <details open={allFiles} onToggle={e=>setAllFiles(e.currentTarget.open)}><summary>전체 파일 트리</summary>{allFiles&&<FileTree files={visibleFiles} selected={selected?.id} disabled={busy} onSelect={select} index={treeIndex}/>}</details>
            {!visibleFiles.length&&<p role="status">일치하는 파일이 없습니다.</p>}
          </nav>
          <div className="source-edit-pane">
            {workspace&&targetPath&&!workspace.files.some(f=>f.path===targetPath)&&<p role="alert">선택한 문제의 파일을 확보하지 못했습니다. 다른 파일을 대신 열지 않았습니다.</p>}
            {selected ? <><h3>{selected.path}</h3><p>{selected.size.toLocaleString()} bytes · {selected.editable ? `${content?.newline ?? 'UTF-8'}${content?.bom ? ' · BOM 보존' : ''}` : '읽기 전용: 바이너리·크기·인코딩 제한'}</p>
              {latest&&<p>현재 저장본 재검사 #{latest.reviewId}: {treeIndex.byPath.get(selected.path)?.length
                ? `연결된 문제 ${treeIndex.byPath.get(selected.path)?.length}건`
                : treeIndex.inspected.has(selected.path)?'검사 범위에서 연결된 문제 미탐지':'검증 불충분 · 파일 검사 여부 미확인'}. 아래 수정 가이드는 원본 근거를 유지합니다.
                {latest.projectId&&<> <a href={`#/projects/${latest.projectId}/findings?review=${latest.reviewId}`}>재검사 상세</a></>}</p>}
              {issues.length>0&&<section className="workspace-file-findings" aria-label="파일의 문제 목록"><h4>이 파일의 원본 분석 결과 · {issues.length}건</h4>{issues.some(i=>i.dependency)&&<p>라이브러리 숫자는 공지·패키지·버전 매칭 수입니다. 중복 설치 경로는 건수에 추가하지 않습니다.</p>}<ul>{issues.map(item=><li key={item.id}><button type="button" disabled={busy} aria-pressed={item.id===issue?.id} onClick={()=>pickIssue(item)}>{item.title} · {item.severity==='UNKNOWN'?'검토 필요':item.severity}{item.line&&item.line>0?` · 원본 ${item.line}행`:''}</button></li>)}</ul></section>}
              {!!index.evidence.get(selected.path)?.size&&<p>다른 파일 문제의 관련 증거가 있습니다. 배지 건수에는 포함하지 않습니다.</p>}
              {issue?.line&&issue.line>0&&(!originalVerified(workspace)||dirty||selected.changed)&&<p>원본 {issue.line}행 · 현재 편집본에 같은 줄이라고 확인할 수 없어 강조하지 않습니다.</p>}
              {selected.editable && content && <><label className="source-code-label" htmlFor="source-code"><span className="editor-file-path">{selected.path}</span><span role="status">{dirty ? pendingSave?'저장 결과 미확인 · 이 탭의 편집':'저장하지 않은 변경' : selected.changed ? workspace.storageMode==='ENCRYPTED_PERSISTENT'?'서버 저장본 · 재검사로 확인 필요':'임시 서버 저장 · 재검사로 확인 필요' : '원본과 동일'}</span><span className="visually-hidden">파일 내용</span>{issue?.line&&issue.line>0&&<span>선택한 문제 · 원본 {issue.line}행</span>}</label>
                <textarea id="source-code" wrap="off" className="source-code" value={text} spellCheck={false} autoCapitalize="off" autoComplete="off" autoCorrect="off" disabled={busy} onChange={e => { setText(e.target.value);if(!pendingSave)setSaveState(null); setApproved(false); setDiffs(null); }} />
                <div className="source-editor-actions"><button type="button" className="primary-button" disabled={busy || !dirty} onClick={() => save(false)}>변경 저장</button>
                  <button type="button" className="secondary-button" disabled={busy || (!selected.changed && !dirty)} onClick={() => save(true)}>원본으로 되돌리기</button></div></>}
            </> : <p>파일을 선택해 주세요.</p>}
          </div>
          <aside className="source-evidence-pane" aria-label="선택 파일의 수정 근거">
            {issue?.dependency&&<><DependencyFindingCard key={issue.id} dependency={issue.dependency} reviewId={result.reviewId} components={result.sca?.components} embedded/><DependencyUpdatePlans key={`plans-${issue.id}`} reviewId={result.reviewId} selectedDependency={issue.dependency}/></>}
            {issue&&!issue.dependency&&<div className="workspace-selected-finding"><h3>{issue.title}</h3><p>{issue.severity==='UNKNOWN'?'검토 필요':issue.severity} · {issue.path}{issue.line&&issue.line>0?`:${issue.line}`:''}</p>
              <p>{issue.code?.message??issue.flow?.riskExplanation}</p><p>{issue.code?.recommendation??issue.flow?.recommendedAction}</p>
              {issue.code?.evidence&&<pre>{issue.code.evidence}</pre>}
              {issue.flow?.evidence.map((e,i)=><p key={i}>Source: {e.source.filePath}:{e.source.line} → Sink: {e.sink.filePath}:{e.sink.line}</p>)}
              <ProblemRepairGuide rule={issue.code?.ruleId??issue.flow?.ruleId??''} v={issue.code}/>
            </div>}
            {!issue&&problemContext&&<div id="workspace-problem-guide"><h3>{problemContext.title}</h3>{selected&&!problemContext.locations.some(l=>l.path===selected.path)&&<p role="note">현재 연 파일은 선택한 문제의 원본 경로와 다릅니다. 이 파일 변경이 해당 문제를 해결한다는 의미가 아닙니다.</p>}{cap.loading?<p role="status">수정 지원 정보를 확인합니다.</p>:cap.problem?<p role="note">지원 정보를 확인하지 못했습니다{cap.problem.status?` (HTTP ${cap.problem.status})`:''}. AI 서버 오류로 단정하지 않으며 수동 수정은 유지합니다.</p>:!cap.value?.providerAvailable?<p role="note">{isDependencyContext&&cap.value?.npmTreePlans?'AI Provider는 비활성화되어 있지만, 의존성 트리 수정안은 AI 없이 npm과 보안 근거로 검증할 수 있습니다.':'현재 AI Provider가 비활성화되어 있습니다. 기본 가이드와 수동 수정을 이용하세요.'}</p>:cap.value.providerOrigin==='MOCK'?<p className="source-label">현재 시험 Provider는 Mock입니다. 실제 모델 호출·품질 검증과 구분합니다.</p>:null}<ProblemRepairGuide rule={isDependencyContext?'NPM_DEPENDENCY_UPDATE':problemContext.ruleId} v={problemContext.vulnerability}/>{problemContext.flow&&<><p>{problemContext.flow.recommendedAction}</p><ol>{problemContext.flow.verificationSteps.map((s,i)=><li key={i}>{s}</li>)}</ol></>}</div>}
            {workspace&&targetPath&&!workspace.files.some(f=>f.path===targetPath)&&<p role="alert">선택한 문제의 파일을 확보하지 못했습니다. 다른 파일을 대신 열지 않았습니다.</p>}
            {selected ? <>
              {!issue?.dependency && selected.editable && content && ((selected.path.endsWith('.properties')&&findings.some(f=>(!issue||issue.code===f)&&['DEBUG_ENABLED','STACKTRACE_EXPOSURE','INSECURE_COOKIE'].includes(f.ruleId)))||(/\.[cm]?[jt]s$/.test(selected.path)&&flowFindings.some(f=>(!issue||issue.flow===f)&&f.ruleId==='TS_SENSITIVE_DATA_EXPOSURE'&&(f.location.kind==='HTTP_RESPONSE'||f.location.kind==='EXPRESS_HTTP_RESPONSE'&&cap.value?.patchScopes?.includes('EXPRESS_DIRECT_ENV_JSON'))))) && <AiPatchPanel initialFinding={issue?(issue.flow?issue.id:issue.code?.vulnerabilityId!=null?String(issue.code.vulnerabilityId):undefined):selected.path===problemContext?.path?(problemContext.flow?"flow:"+problemContext.flow.findingId:problemContext.vulnerability?.vulnerabilityId!=null?String(problemContext.vulnerability.vulnerabilityId):undefined):undefined} key={`${selected.id}:${issue?.id??''}`} workspace={workspace} file={selected} content={content} findings={issue?findings.filter(f=>f===issue.code):findings} flowFindings={issue?flowFindings.filter(f=>f===issue.flow):flowFindings} dirty={dirty} disabled={busy}
                onApplied={async next => { setWorkspace(next);setDiffs(null);setApproved(false);setSelected(next.files.find(f => f.id === selected.id) ?? null);
                  const value=await loadEditingFile(next.id,selected.id);setContent(value);setText(value.text.replace(/\r\n/g,'\n')); }} />}
              {(findings.length > 0 || flowFindings.length > 0) && <details aria-label="기준 분석 근거"><summary>기준 commit의 원본 근거</summary>
                {findings.map((v, i) => <div key={`rule-${i}`}><p>{v.ruleId} · 원본 {v.line}행 · {v.message}</p><p>{v.recommendation}</p></div>)}
                {flowFindings.map(f => <details key={f.findingId}><summary>{f.title} · 원본 {f.location.line}행</summary><p>{f.riskExplanation}</p><p>{f.recommendedAction}</p>
                  <ul>{f.verificationSteps.map((s,i) => <li key={i}>{s}</li>)}</ul></details>)}
                <p>편집 후 줄 위치는 달라질 수 있습니다. 수정 완료는 재검사로 확인해야 합니다.</p></details>}
              {!issue?.dependency&&findings.length===0&&flowFindings.length===0&&<p>{problemContext?.locations.some(l=>l.path===selected.path)?'선택한 문제의 함수 전달 근거에 연결된 파일입니다. 원본 근거와 출력 문맥을 확인하고 수동 편집 후 재검사하세요. 자동 Patch 지원을 의미하지 않습니다.':'이 파일에 연결된 코드 Finding은 없어요. 라이브러리 공지와 코드 Patch 지원은 별개이며, 수동 편집 후 재검사할 수 있습니다.'}</p>}
            </> : <p>파일을 선택하면 연결된 분석 근거를 확인할 수 있습니다.</p>}
          </aside>
        </div>
        {workspace.changedFileIds.length===0&&!dirty&&<p role="status">수정한 파일이 아직 없어요. 파일을 선택하고 변경 내용을 저장해 주세요.</p>}
        <div className="source-editor-next"><button type="button" className="primary-button" disabled={busy || dirty || workspace.changedFileIds.length===0} onClick={()=>setStage('diff')}>변경 사항 검토</button>{dirty&&<p>저장하지 않은 변경이 있습니다.</p>}</div>
        </div>
        <div className="source-export" hidden={stage!=='diff'}><h3>수정 내용 확인</h3><p>변경 파일의 출처와 Diff를 확인한 뒤 다운로드를 승인하세요. 원본은 보존됩니다.</p>
          {workspace.changedFileIds.length === 0 ? <><p>수정한 파일이 아직 없어요.</p><button type="button" onClick={()=>setStage('edit')}>파일 편집으로 돌아가기</button></> : <>
          <ul>{workspace.files.filter(f => f.changed).map(f => <li key={f.id}>{f.path}</li>)}</ul>
          <button type="button" className="secondary-button" disabled={busy || dirty || workspace.changedFileIds.length === 0} onClick={reviewDiff}>전체 변경 Diff 확인</button>
          {dirty && <p>현재 편집 내용을 저장한 후 전체 변경을 확인해 주세요.</p>}
          {diffs&&<WorkspaceDiffReview heading={false} files={diffs.map(diff=>({path:workspace.files.find(f=>f.id===diff.fileId)?.path??'파일 위치 미확인',patch:diff.patch,origin:diff.changeOrigin,provenance:diff.provenance}))}/>}

          {diffs && <label className="source-export-approval"><input type="checkbox" checked={approved} disabled={busy} onChange={e => setApproved(e.target.checked)} />수정본 버전 {workspace.revision}의 변경 {workspace.changedFileIds.length}개를 검토했으며 다운로드를 승인합니다.</label>}
          <div className="source-editor-actions"><button type="button" className="secondary-button" disabled={busy || !approved || !diffs || dirty} onClick={() => download('zip')}>수정본 ZIP 다운로드</button>
            <button type="button" className="secondary-button" disabled={busy || !approved || !diffs || dirty} onClick={() => download('patch')}>Patch 다운로드</button></div>
          <p>다운로드는 보안 문제 해결 판정이 아닙니다. 적용 후 테스트와 STANDARD 재검사가 필요합니다.</p>
          <button type="button" className="primary-button" disabled={busy || dirty} onClick={()=>setStage('scan')}>수정본 검사로 이동</button></>}
        </div>
      </>}
    </>}
  </section>;
}
