import { useEffect, useRef, useState } from 'react';
import { applyAiPatch, generateAiPatch, listAiPatches, patchProvider, prepareAiPatch, rejectAiPatch } from '../api/editingApi';
import type { AiPatch, EditingContent, EditingFile, EditingWorkspace, PatchProvider } from '../api/editingApi';
import type { Vulnerability } from '../types/securityReview';

const states: Record<string,string> = { APPROVAL_REQUIRED: '코드 전송 동의 대기', GENERATING: '수정안 생성 중', PROPOSED: '제안 · 미적용',
  REJECTED: '거절됨 · 변경 없음', ACCEPTED: '작업 공간 적용됨 · 해결 미검증', STALE: '코드 변경으로 적용 불가', INVALID: '유효하지 않은 응답', FAILED: '생성 실패', NEEDS_REVIEW: '추가 확인 필요 · 적용 불가' };
export function AiPatchPanel({ workspace, file, content, findings, dirty, disabled, onApplied }: {
  workspace: EditingWorkspace; file: EditingFile; content: EditingContent; findings: Vulnerability[]; dirty: boolean; disabled: boolean;
  onApplied: (value: EditingWorkspace) => Promise<void>;
}) {
  const [provider, setProvider] = useState<PatchProvider | null>(null);
  const [finding, setFinding] = useState('');
  const [proposals, setProposals] = useState<AiPatch[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [pending, setPending] = useState(''), [error, setError] = useState('');
  const [consented, setConsented] = useState(false), [accepted, setAccepted] = useState(false);
  const active = useRef(true);
  useEffect(() => { active.current = true; patchProvider().then(v => { if (active.current) setProvider(v); }).catch(() => { if (active.current) setError('AI Provider 상태를 확인하지 못했습니다. 수동 편집은 계속할 수 있습니다.'); }); return () => { active.current = false; }; }, []);
  useEffect(() => { let current = true;
    listAiPatches(workspace.id).then(v => { if (current && active.current) setProposals(v.filter(p => p.fileId === file.id)); })
      .catch(() => { if (current && active.current) setError('제안을 불러오지 못했습니다. 만료 여부를 확인해 주세요.'); });
    setConsented(false); setAccepted(false);
    return () => { current = false; };
  }, [workspace.id, workspace.revision, file.id]);
  const candidates = findings.filter(v => v.vulnerabilityId != null && ['DEBUG_ENABLED','STACKTRACE_EXPOSURE','INSECURE_COOKIE'].includes(v.ruleId));
  const selected = proposals.find(p => p.id === selectedId) ?? proposals[proposals.length - 1];
  const update = (value: AiPatch) => { if (active.current) { setProposals(old => [...old.filter(p => p.id !== value.id), value]); setSelectedId(value.id); } };
  const perform = async (name: string, fn: () => Promise<void>) => {
    if (pending) return; setPending(name); setError('');
    try { await fn(); } catch (e) { if (active.current) setError(e instanceof Error ? e.message : 'AI 제안을 처리하지 못했습니다. 수동 편집은 계속할 수 있습니다.'); }
    finally { if (active.current) setPending(''); }
  };
  const prepare = () => void perform('prepare', async () => { update(await prepareAiPatch(workspace,file,content,Number(finding))); setConsented(false); setAccepted(false); });
  const generate = () => void perform('generate', async () => {
    if (!selected || !consented) return;
    update({ ...selected, state: 'GENERATING' }); setConsented(false);
    update(await generateAiPatch(workspace.id,selected));
  });
  const reject = async () => {
    if (!selected) return;
    setError('');
    try { update(await rejectAiPatch(workspace.id,selected.id)); setConsented(false); setAccepted(false); }
    catch (e) { if (active.current) setError(e instanceof Error ? e.message : '거절 요청을 확인하지 못했습니다.'); }
  };
  const apply = () => void perform('apply', async () => {
    if (!selected || !accepted || dirty) return;
    const next = await applyAiPatch(workspace.id,selected);
    update({ ...selected, state: 'ACCEPTED' }); setAccepted(false); await onApplied(next);
  });
  const eligible = workspace.identityStatus === 'EXACT_GIT_COMMIT' && file.path.endsWith('.properties');
  return <section className="source-ai-patch" aria-label="AI 보안 수정안">
    <h3>AI 보안 수정안</h3>
    <p>제안 생성은 파일을 바꾸지 않습니다. 검토 후 적용해도 실제 보안 문제 해결 여부는 재검사해야 합니다.</p>
    {!eligible ? <p>원본 commit과 일치하는 단순 .properties 설정만 지원합니다. ZIP 원본 미검증·다른 코드 유형은 수동 검토가 필요합니다.</p>
      : !provider?.available ? <p>AI 수정 Provider가 준비되지 않았습니다. 수동 편집과 기존 해결 가이드는 사용할 수 있습니다.</p>
      : <><p>Provider: {provider.name} · 모델: {provider.model} · 외부 전송 및 비용 발생 가능</p>
        {candidates.length === 0 ? <p>이 파일에 자동 수정 범위로 연결할 수 있는 Finding이 없습니다. 권한·RLS·SCA·동적 흐름은 추가 검토 대상입니다.</p>
          : <><label htmlFor="patch-finding">수정할 분석 항목</label><select id="patch-finding" value={finding} disabled={disabled || !!pending} onChange={e => setFinding(e.target.value)}>
            <option value="">항목 선택</option>{candidates.map(v => <option value={v.vulnerabilityId!} key={v.vulnerabilityId}>{v.ruleId} · 원본 {v.line}행</option>)}</select>
            <button type="button" className="secondary-button" disabled={disabled || !!pending || dirty || !finding || !content.currentHash} onClick={prepare}>AI 수정안 전송 범위 확인</button></>}
      </>}
    {error && <p role="alert" className="error-message">{error}</p>}
    {proposals.length > 1 && <label>수정 제안 이력<select value={selected?.id ?? ''} disabled={!!pending} onChange={e => { setSelectedId(e.target.value);setConsented(false);setAccepted(false); }}>
      {proposals.map((p,i) => <option key={p.id} value={p.id}>{i+1}. {p.ruleId} · {states[p.state] ?? p.state}</option>)}</select></label>}
    {selected && <div className="source-ai-proposal">
      <h4>{states[selected.state] ?? '알 수 없는 제안 상태'}</h4>
      <p>{file.path} · 현재 {selected.startLine}행 · 기준 revision {selected.revision} · {selected.ruleId}</p>
      <p>{selected.explanation}</p>
      {selected.state === 'APPROVAL_REQUIRED' && <>
        <p>전송 대상: 아래 설정 한 줄과 Finding 규칙·파일 ID·행·내용 해시. 다른 파일과 주변 코드는 전송하지 않습니다.</p>
        <pre className="source-ai-code">{selected.before}</pre>
        <p>{selected.provider.name} / {selected.provider.model} · 저장소 밖 Provider로 전송합니다. 민감정보가 보이면 동의하지 마세요.</p>
        <label className="source-export-approval"><input type="checkbox" checked={consented} disabled={!!pending || dirty} onChange={e => setConsented(e.target.checked)} />이 코드 범위의 외부 전송과 유료 호출 가능성에 동의합니다.</label>
        <button type="button" className="primary-button" disabled={disabled || !!pending || dirty || !consented} onClick={generate}>동의한 코드로 AI 수정안 생성</button>
      </>}
      {selected.state === 'GENERATING' && <p role="status">코드를 변경하지 않고 제안을 생성하고 있습니다. 취소해도 이미 전송한 요청의 처리·요금 취소는 보증하지 않습니다.</p>}
      {selected.diff && <div className="source-diff"><h4>현재 수정본 → AI 제안</h4><pre tabIndex={0}>{selected.diff}</pre></div>}
      {selected.verificationSteps.length > 0 && <><h4>수정 후 확인</h4><ul>{selected.verificationSteps.map((s,i) => <li key={i}>{s}</li>)}</ul></>}
      <ul>{selected.limitations.map((s,i) => <li key={i}>{s}</li>)}</ul>
      {selected.state === 'PROPOSED' && <><label className="source-export-approval"><input type="checkbox" checked={accepted} disabled={disabled || dirty || !!pending} onChange={e => setAccepted(e.target.checked)} />Diff와 미확인 조건을 검토했고 현재 작업 공간에만 적용하도록 승인합니다.</label>
        <button type="button" className="primary-button" disabled={disabled || dirty || !!pending || !accepted} onClick={apply}>검토한 AI 수정안 적용</button></>}
      {['APPROVAL_REQUIRED','GENERATING','PROPOSED','NEEDS_REVIEW'].includes(selected.state) && <button type="button" className="secondary-button" disabled={disabled} onClick={() => void reject()}>{selected.state === 'GENERATING' ? '생성 취소·거절' : '제안 거절'}</button>}
    </div>}
    {dirty && <p>저장하지 않은 편집이 있습니다. AI 생성·적용 전에 직접 저장하거나 되돌려 주세요.</p>}
  </section>;
}
