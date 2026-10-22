import { useEffect, useRef, useState } from 'react';
import { createEditingWorkspace, deleteEditingWorkspace, exportEditingWorkspace, loadEditingDiff, loadEditingFile, loadEditingWorkspace, saveEditingFile } from '../api/editingApi';
import type { EditingContent, EditingDiff, EditingFile, EditingWorkspace } from '../api/editingApi';
import type { SecurityReviewResponse } from '../types/securityReview';
import { AiPatchPanel } from './AiPatchPanel';
import { WorkspaceScanPanel } from './WorkspaceScanPanel';

interface TreeNode { name: string; children: Map<string, TreeNode>; file?: EditingFile }
function FileTree({ files, selected, disabled, onSelect }: { files: EditingFile[]; selected?: string; disabled: boolean; onSelect: (file: EditingFile) => void }) {
  const root: TreeNode = { name: '', children: new Map() };
  for (const file of files) {
    let node = root;
    for (const name of file.path.split('/')) { if (!node.children.has(name)) node.children.set(name, { name, children: new Map() }); node = node.children.get(name)!; }
    node.file = file;
  }
  const render = (node: TreeNode): React.ReactNode => <ul>{[...node.children.values()].map(child => <li key={child.name}>
    {child.children.size || child.file?.directory ? <details open><summary>{child.name}</summary>{render(child)}</details>
      : <button type="button" title={child.file?.path} disabled={disabled} aria-current={selected === child.file?.id ? 'true' : undefined}
          onClick={() => child.file && onSelect(child.file)}>{child.file?.changed ? '* ' : ''}{child.name}{!child.file?.editable ? ' (읽기 전용)' : ''}</button>}
  </li>)}</ul>;
  return render(root);
}

export function SourceEditingWorkspace({ result, onBack, initialPath }: { result: SecurityReviewResponse; onBack: () => void; initialPath?: string }) {
  const key = `securedeploy.editing.${result.reviewId}`;
  const [workspace, setWorkspace] = useState<EditingWorkspace | null>(null);
  const [selected, setSelected] = useState<EditingFile | null>(null);
  const [content, setContent] = useState<EditingContent | null>(null);
  const [text, setText] = useState('');
  const [zip, setZip] = useState<File | null>(null);
  const [busy, setBusy] = useState(false), [error, setError] = useState('');
  const [diffs, setDiffs] = useState<EditingDiff[] | null>(null), [approved, setApproved] = useState(false);
  const [expired, setExpired] = useState(false);
  const [stage, setStage] = useState<'edit'|'diff'|'scan'>('edit');
  const [pane, setPane] = useState<'files'|'code'|'evidence'>('files');
  const [evidenceOpen, setEvidenceOpen] = useState(false);
  const mounted = useRef(true);
  const dirty = content !== null && text !== content.text.replace(/\r\n/g, '\n');
  useEffect(() => {
    mounted.current = true;
    const stored = sessionStorage.getItem(key);
    if (stored) {
      setBusy(true);
      loadEditingWorkspace(stored).then(value => { if (mounted.current) setWorkspace(value); })
        .catch(() => { sessionStorage.removeItem(key); if (mounted.current) setError('이전 작업 공간이 만료되었거나 접근할 수 없습니다. 원본을 다시 확보해 주세요.'); })
        .finally(() => { if (mounted.current) setBusy(false); });
    }
    return () => { mounted.current = false; };
  }, [key]);
  useEffect(() => {
    const check = () => { if (workspace && Date.parse(workspace.expiresAt) <= Date.now()) { setExpired(true); setText(''); setContent(null); setDiffs(null); setApproved(false); } };
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
    try { await action(); } catch (e) { if (mounted.current) setError(e instanceof Error ? e.message : '요청을 완료하지 못했습니다.'); }
    finally { if (mounted.current) setBusy(false); }
  };
  const start = () => run(async () => {
    if (!result.reviewId) return;
    const value = await createEditingWorkspace(result.reviewId, result.sourceType === 'ZIP' ? zip ?? undefined : undefined);
    if (mounted.current) { setWorkspace(value); setExpired(false); sessionStorage.setItem(key, value.id); }
  });
  const select = (file: EditingFile) => void run(async () => {
    if (dirty && !window.confirm('저장하지 않은 편집을 버리고 다른 파일을 열까요?')) return;
    setDiffs(null); setApproved(false); setSelected(file); setContent(null); setText('');
    setPane('code');
    if (workspace && file.editable) {
      const value = await loadEditingFile(workspace.id, file.id);
      if (value.revision !== workspace.revision) throw new Error('다른 탭에서 변경되었습니다. 작업 공간을 새로고침해 주세요.');
      setContent(value); setText(value.text.replace(/\r\n/g, '\n'));
    }
  });
  useEffect(()=>{
    if(workspace&&!selected&&initialPath&&!busy){const file=workspace.files.find(f=>f.path===initialPath);if(file)select(file);}
  },[workspace?.id,initialPath,busy,selected?.id]);
  const save = (revert: boolean) => void run(async () => {
    if (!workspace || !selected) return;
    if (revert && !window.confirm('이 파일의 변경을 모두 취소하고 불변 원본으로 되돌릴까요?')) return;
    const next = await saveEditingFile(workspace, selected, text, revert);
    setWorkspace(next); setDiffs(null); setApproved(false); setSelected(next.files.find(f => f.id === selected.id) ?? null);
    const value = await loadEditingFile(next.id, selected.id); setContent(value); setText(value.text.replace(/\r\n/g, '\n'));
  });
  const reviewDiff = () => void run(async () => {
    if (!workspace || dirty) return;
    const values: EditingDiff[] = [];
    for (const id of workspace.changedFileIds) {
      const value = await loadEditingDiff(workspace.id, id);
      if (value.revision !== workspace.revision) throw new Error('변경 revision이 다릅니다. 다시 불러와 주세요.');
      values.push(value);
    }
    setDiffs(values); setApproved(false);
  });
  const download = (format: 'zip' | 'patch') => void run(async () => {
    if (!workspace || !approved || diffs === null || dirty) return;
    const blob = await exportEditingWorkspace(workspace, format);
    const url = URL.createObjectURL(blob), link = document.createElement('a');
    link.href = url; link.download = `securedeploy-edited-r${workspace.revision}.${format}`;
    document.body.appendChild(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    setApproved(false);
  });
  const clear = () => void run(async () => {
    if (workspace && !window.confirm('원본과 편집 내용을 삭제하고 작업 공간을 닫을까요? 복구할 수 없습니다.')) return;
    if (workspace && !expired) await deleteEditingWorkspace(workspace.id);
    sessionStorage.removeItem(key); setWorkspace(null); setContent(null); setSelected(null); setText(''); setDiffs(null); setApproved(false); setExpired(false);
  });
  const findings = selected && workspace?.identityStatus === 'EXACT_GIT_COMMIT'
    ? result.vulnerabilities.filter(v => v.filePath.replace(/\\/g, '/') === selected.path) : [];
  const flowFindings = selected && workspace?.identityStatus === 'EXACT_GIT_COMMIT'
    ? [...(result.serverAnalysis?.validatedFindings ?? []), ...(result.serverAnalysis?.pythonAnalysis?.validatedFindings ?? [])]
      .filter(f => f.location.filePath.replace(/\\/g, '/') === selected.path) : [];
  return <section className={`source-editor stage-${stage} pane-${pane} ${evidenceOpen?'evidence-open':''}`} aria-label="수정 작업 공간">
    <header className="source-editor-header"><div><h2>수정 작업 공간</h2><p>{result.projectName} · Review {result.reviewId}</p></div>
      <button type="button" className="secondary-button" aria-label="분석 결과로 돌아가기" disabled={busy} onClick={() => { if (!dirty || window.confirm('저장하지 않은 편집을 버리고 결과로 돌아갈까요?')) onBack(); }}>결과로 돌아가기</button></header>
    {error && <p className="error-message" role="alert">{error}</p>}
    {!workspace ? <div className="source-editor-acquire">
      <p>원본은 30분 동안 임시 보관되며 서버 재시작 시 사라집니다. 편집 내용은 자동 재검사되거나 GitHub에 반영되지 않습니다.</p>
      {result.sourceType === 'ZIP' ? <><p role="note">과거 ZIP과 일치하는지 검증할 기록이 없습니다. 과거 경고 위치를 확정 연결하지 않으며 다운로드 후 새로 분석해야 합니다.</p>
        <label>원본 ZIP <input type="file" accept=".zip,application/zip" disabled={busy} onChange={e => setZip(e.target.files?.[0] ?? null)} /></label></>
        : <p>현재 읽기 권한을 확인하고 분석 당시 commit만 가져옵니다. 해당 commit을 확보하지 못하면 작업을 중단합니다.</p>}
      {result.sourceType === 'WORKSPACE' && <p role="note">수정본 Review에는 전체 소스를 보관하지 않습니다. 기존 작업 공간을 이용하거나 다운로드한 ZIP으로 새 분석을 시작해 주세요.</p>}
      <button className="primary-button" type="button" disabled={busy || !result.reviewId || !result.sourceType || result.sourceType === 'WORKSPACE' || (result.sourceType === 'ZIP' && !zip)} onClick={() => void start()}>{busy ? '원본 확인 중...' : '원본 확보 후 작업 공간 시작'}</button>
    </div> : <>
      <div className="source-editor-status"><p><strong>revision {workspace.revision}</strong> · 만료 {new Date(workspace.expiresAt).toLocaleTimeString()} · 변경 {workspace.changedFileIds.length}개</p>
        <details><summary>원본·해시 정보</summary><p className="source-revision">원본: {workspace.sourceRevision}</p></details>
        {workspace.identityStatus === 'UNVERIFIED_REUPLOAD' && <p role="note">원본 일치 미검증 · 기존 Finding 위치 연결 안 함 · 수정 후 새 분석 필요</p>}
        {expired && <p role="alert">작업 공간이 만료되었습니다. 원본을 다시 확보해 주세요.</p>}
        <button type="button" className="secondary-button" disabled={busy} onClick={clear}>작업 공간 삭제</button>
      </div>
      <nav className="editing-stages" aria-label="수정 단계">{([['edit','코드 편집'],['diff','변경 검토 · 다운로드'],['scan','재검사 · 비교']] as const).map(([id,label])=><button key={id} type="button" aria-current={stage===id?'step':undefined} onClick={()=>setStage(id)}>{label}</button>)}</nav>
      <div hidden={stage!=='scan'}><WorkspaceScanPanel workspace={workspace} original={result} disabled={busy || dirty || expired} /></div>
      {!expired && <>
        <div hidden={stage!=='edit'}>
        <nav className="editing-panes" aria-label="편집 화면">{([['files','파일'],['code','코드'],['evidence','수정 근거 · AI']] as const).map(([id,label])=><button key={id} type="button" aria-pressed={pane===id} onClick={()=>{setPane(id);if(id==='evidence')setEvidenceOpen(true);}}>{label}</button>)}</nav>
        <div className="editor-toolbar"><span>{selected?.path ?? '파일 선택'}</span><button type="button" className="secondary-button" aria-expanded={evidenceOpen} onClick={()=>setEvidenceOpen(!evidenceOpen)}>{evidenceOpen?'수정 근거 접기':'수정 근거 열기'}</button></div>
        <div className="source-editor-layout">
          <nav className="source-file-tree" aria-label="프로젝트 파일"><FileTree files={workspace.files} selected={selected?.id} disabled={busy} onSelect={select} /></nav>
          <div className="source-edit-pane">
            {selected ? <><h3>{selected.path}</h3><p>{selected.size.toLocaleString()} bytes · {selected.editable ? `${content?.newline ?? 'UTF-8'}${content?.bom ? ' · BOM 보존' : ''}` : '읽기 전용: 바이너리·크기·인코딩 제한'}</p>
              {selected.editable && content && <><label className="source-code-label" htmlFor="source-code">파일 내용{dirty ? ' · 저장하지 않은 변경' : ''}</label>
                <textarea id="source-code" className="source-code" value={text} spellCheck={false} autoCapitalize="off" autoComplete="off" autoCorrect="off" disabled={busy} onChange={e => { setText(e.target.value); setApproved(false); setDiffs(null); }} />
                <div className="source-editor-actions"><button type="button" className="primary-button" disabled={busy || !dirty} onClick={() => save(false)}>변경 저장</button>
                  <button type="button" className="secondary-button" disabled={busy || (!selected.changed && !dirty)} onClick={() => save(true)}>원본으로 되돌리기</button></div></>}
            </> : <p>파일을 선택해 주세요.</p>}
          </div>
          <aside className="source-evidence-pane" aria-label="선택 파일의 수정 근거">
            {selected ? <>
              {selected.editable && content && <AiPatchPanel key={selected.id} workspace={workspace} file={selected} content={content} findings={findings} flowFindings={flowFindings} dirty={dirty} disabled={busy}
                onApplied={async next => { setWorkspace(next);setDiffs(null);setApproved(false);setSelected(next.files.find(f => f.id === selected.id) ?? null);
                  const value=await loadEditingFile(next.id,selected.id);setContent(value);setText(value.text.replace(/\r\n/g,'\n')); }} />}
              {(findings.length > 0 || flowFindings.length > 0) && <aside aria-label="기준 분석 근거"><h3>기준 commit의 경고 위치</h3>
                {findings.map((v, i) => <div key={`rule-${i}`}><p>{v.ruleId} · 원본 {v.line}행 · {v.message}</p><p>{v.recommendation}</p></div>)}
                {flowFindings.map(f => <details key={f.findingId}><summary>{f.title} · 원본 {f.location.line}행</summary><p>{f.riskExplanation}</p><p>{f.recommendedAction}</p>
                  <ul>{f.verificationSteps.map((s,i) => <li key={i}>{s}</li>)}</ul></details>)}
                <p>편집 후 줄 위치는 달라질 수 있습니다. 수정 완료는 재검사로 확인해야 합니다.</p></aside>}
            </> : <p>파일을 선택하면 연결된 분석 근거를 확인할 수 있습니다.</p>}
          </aside>
        </div>
        <div className="source-editor-next"><button type="button" className="primary-button" disabled={busy || dirty} onClick={()=>setStage('diff')}>변경 사항 검토</button>{dirty&&<p>저장하지 않은 변경이 있습니다.</p>}</div>
        </div>
        <div className="source-export" hidden={stage!=='diff'}><h3>변경 검토 및 다운로드</h3>
          {workspace.changedFileIds.length === 0 && <p>변경 없음</p>}
          <ul>{workspace.files.filter(f => f.changed).map(f => <li key={f.id}>{f.path}</li>)}</ul>
          <button type="button" className="secondary-button" disabled={busy || dirty || workspace.changedFileIds.length === 0} onClick={reviewDiff}>전체 변경 Diff 확인</button>
          {dirty && <p>현재 편집 내용을 저장한 후 전체 변경을 확인해 주세요.</p>}
          {diffs && diffs.map(diff => <div className="source-diff" key={diff.fileId}><h4>{workspace.files.find(f => f.id === diff.fileId)?.path}</h4><pre tabIndex={0}>{diff.patch || '변경 없음'}</pre></div>)}
          {diffs && <label className="source-export-approval"><input type="checkbox" checked={approved} disabled={busy} onChange={e => setApproved(e.target.checked)} />revision {workspace.revision}의 변경 {workspace.changedFileIds.length}개를 검토했으며 다운로드를 승인합니다.</label>}
          <div className="source-editor-actions"><button type="button" className="secondary-button" disabled={busy || !approved || !diffs || dirty} onClick={() => download('zip')}>수정본 ZIP 다운로드</button>
            <button type="button" className="secondary-button" disabled={busy || !approved || !diffs || dirty} onClick={() => download('patch')}>Patch 다운로드</button></div>
          <p>다운로드는 보안 문제 해결 판정이 아닙니다. 적용 후 테스트와 STANDARD 재검사가 필요합니다.</p>
          <button type="button" className="primary-button" disabled={busy || dirty} onClick={()=>setStage('scan')}>수정본 검사로 이동</button>
        </div>
      </>}
    </>}
  </section>;
}
