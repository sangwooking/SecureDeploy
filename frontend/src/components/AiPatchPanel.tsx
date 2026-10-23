import { useEffect, useRef, useState } from 'react';
import { applyAiPatch, generateAiPatch, listAiPatches, patchProvider, prepareAiPatch, rejectAiPatch, fixOption, prepareDeterministicPatch } from '../api/editingApi';
import type { AiPatch, EditingContent, EditingFile, EditingWorkspace, PatchProvider, FixOption } from '../api/editingApi';
import type { Vulnerability } from '../types/securityReview';
import type { ServerAnalysisSnapshot } from '../types/serverAnalysis';

const states: Record<string,string> = { APPROVAL_REQUIRED: '코드 전송 동의 대기', GENERATING: '수정안 생성 중', PROPOSED: '제안 · 미적용',
  REJECTED: '거절됨 · 변경 없음', ACCEPTED: '작업 공간 적용됨 · 해결 미검증', STALE: '코드 변경으로 적용 불가', INVALID: '유효하지 않은 응답', FAILED: '생성 실패', NEEDS_REVIEW: '추가 확인 필요 · 적용 불가' };
export function AiPatchPanel({ workspace, file, content, findings, flowFindings = [], dirty, disabled, onApplied }: {
  workspace: EditingWorkspace; file: EditingFile; content: EditingContent; findings: Vulnerability[]; dirty: boolean; disabled: boolean;
  flowFindings?: NonNullable<ServerAnalysisSnapshot['validatedFindings']>;
  onApplied: (value: EditingWorkspace) => Promise<void>;
}) {
  const [provider, setProvider] = useState<PatchProvider | null>(null);
  const [finding, setFinding] = useState('');
  const [option,setOption]=useState<FixOption|null>(null);
  const [proposals, setProposals] = useState<AiPatch[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [pending, setPending] = useState(''), [error, setError] = useState('');
  const [consented, setConsented] = useState(false), [accepted, setAccepted] = useState(false);
  const [compatibilityAccepted,setCompatibilityAccepted]=useState(false);
  const active = useRef(true);
  useEffect(()=>{setFinding('');setSelectedId('');setProposals([]);},[file.id,workspace.id]);
  useEffect(()=>{let current=true;setOption(null);
    if(finding&&!dirty&&!disabled&&content.revision===workspace.revision&&content.fileId===file.id)fixOption(workspace,file,content,finding.startsWith('flow:')?0:Number(finding),finding.startsWith('flow:')?finding.slice(5):undefined)
      .then(v=>{if(current)setOption(v);}).catch(()=>{if(current)setOption({method:'MANUAL_REVIEW',reason:'수정 범위를 확인하지 못했습니다. 최신 파일을 확인하거나 수동 편집해 주세요.'});});
    return()=>{current=false;};
  },[finding,workspace.id,workspace.revision,file.id,content.currentHash,content.revision,content.fileId,dirty,disabled]);
  useEffect(() => { active.current = true; patchProvider().then(v => { if (active.current) setProvider(v); }).catch(() => { if (active.current) setError('AI Provider 상태를 확인하지 못했습니다. 수동 편집은 계속할 수 있습니다.'); }); return () => { active.current = false; }; }, []);
  useEffect(() => { let current = true;
    listAiPatches(workspace.id).then(v => { if (current && active.current) setProposals(v.filter(p => p.fileId === file.id)); })
      .catch(() => { if (current && active.current) setError('제안을 불러오지 못했습니다. 만료 여부를 확인해 주세요.'); });
    setConsented(false); setAccepted(false);setCompatibilityAccepted(false);
    return () => { current = false; };
  }, [workspace.id, workspace.revision, file.id]);
  const candidates = findings.filter(v => v.vulnerabilityId != null && ['DEBUG_ENABLED','STACKTRACE_EXPOSURE','INSECURE_COOKIE'].includes(v.ruleId));
  const flows=flowFindings.filter(f=>f.ruleId==='TS_SENSITIVE_DATA_EXPOSURE'&&f.location.kind==='HTTP_RESPONSE');
  const selected = proposals.find(p => p.id === selectedId) ?? proposals[proposals.length - 1];
  const deterministic=selected?.method==='DETERMINISTIC_FIX';
  const update = (value: AiPatch) => { if (active.current) { setProposals(old => [...old.filter(p => p.id !== value.id), value]); setSelectedId(value.id); } };
  const perform = async (name: string, fn: () => Promise<void>) => {
    if (pending) return; setPending(name); setError('');
    try { await fn(); } catch (e) { if (active.current) setError(e instanceof Error ? e.message : 'AI 제안을 처리하지 못했습니다. 수동 편집은 계속할 수 있습니다.'); }
    finally { if (active.current) setPending(''); }
  };
  const prepare = () => void perform('prepare', async () => { setCompatibilityAccepted(false);update(await prepareAiPatch(workspace,file,content,finding.startsWith('flow:')?0:Number(finding),finding.startsWith('flow:')?finding.slice(5):undefined)); setConsented(false); setAccepted(false); });
  const automatic=()=>void perform('automatic',async()=>{if(option?.method!=='DETERMINISTIC_FIX'||!finding.startsWith('flow:'))return;
    setCompatibilityAccepted(false);setConsented(false);setAccepted(false);
    update(await prepareDeterministicPatch(workspace,file,content,finding.slice(5)));
  });
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
    if (!selected || !accepted || dirty || (selected.flowFindingId&&!compatibilityAccepted)) return;
    const next = await applyAiPatch(workspace.id,selected);
    update({ ...selected, state: 'ACCEPTED' }); setAccepted(false); await onApplied(next);
  });
  const eligible = workspace.identityStatus === 'EXACT_GIT_COMMIT' && (file.path.endsWith('.properties')||file.path.endsWith('.ts'));
  return <section className="source-ai-patch" aria-label="보안 수정안">
    <h3>보안 수정안</h3>
    <p>제안 생성은 파일을 바꾸지 않습니다. 검토 후 적용해도 실제 보안 문제 해결 여부는 재검사해야 합니다.</p>
    {!!flows.length&&<p>Deno TypeScript 객체 응답의 환경값 필드 제거만 제한적으로 지원합니다. 서버가 코드 범위를 확인하지 못하면 전송하지 않고 수동 검토를 안내합니다.</p>}
    {!eligible ? <p>원본 commit과 일치하는 단순 .properties 설정 또는 제한된 Deno 객체 응답만 지원합니다. ZIP 원본 미검증·다른 코드 유형은 수동 검토가 필요합니다.</p>
      : <>{provider?.available?<p>AI 선택 시 Provider: {provider.name} · 모델: {provider.model} · 외부 전송 및 비용 발생 가능</p>:<p>AI 수정 Provider가 준비되지 않았습니다. 지원되는 자동 수정안과 수동 편집은 사용할 수 있습니다.</p>}
        {candidates.length === 0 && flows.length === 0 ? <p>이 파일에 자동 수정 범위로 연결할 수 있는 Finding이 없습니다. 권한·RLS·SCA·동적 흐름은 추가 검토 대상입니다.</p>
          : <><label htmlFor="patch-finding">수정할 분석 항목</label><select id="patch-finding" value={finding} disabled={disabled || !!pending} onChange={e => setFinding(e.target.value)}>
            <option value="">항목 선택</option>{candidates.map(v => <option value={v.vulnerabilityId!} key={v.vulnerabilityId}>{v.ruleId} · 원본 {v.line}행</option>)}
            {flows.map(f=><option key={f.findingId} value={`flow:${f.findingId}`}>환경값 응답 검토 · 원본 {f.location.line}행</option>)}</select>
            {finding&&!option&&<p role="status">수정 가능한 범위를 확인하고 있습니다.</p>}
            {option&&<p>{option.method==='DETERMINISTIC_FIX'?'자동 수정 가능':option.method==='AI_ASSISTED'?'AI 제안 지원':option.method==='MANUAL_REVIEW'?'수동 검토 필요':'수정 기능 미지원'} · {option.reason}</p>}
            {option?.method==='DETERMINISTIC_FIX'&&<button type="button" className="primary-button" disabled={disabled||!!pending||dirty||!content.currentHash} onClick={automatic}>자동 수정안 만들기</button>}
            {provider?.available&&(option?.method==='DETERMINISTIC_FIX'||option?.method==='AI_ASSISTED')&&<button type="button" className="secondary-button" disabled={disabled || !!pending || dirty || !finding || !content.currentHash} onClick={prepare}>AI 수정안 전송 범위 확인</button>}</>}
      </>}
    {error && <p role="alert" className="error-message">{error}</p>}
    {proposals.length > 1 && <label>수정 제안 이력<select value={selected?.id ?? ''} disabled={!!pending} onChange={e => { setSelectedId(e.target.value);setConsented(false);setAccepted(false);setCompatibilityAccepted(false); }}>
      {proposals.map((p,i) => <option key={p.id} value={p.id}>{i+1}. {p.method==='DETERMINISTIC_FIX'?'자동':'AI'} · {p.ruleId} · {states[p.state] ?? p.state}</option>)}</select></label>}
    {selected && <div className="source-ai-proposal">
      <h4>{states[selected.state] ?? '알 수 없는 제안 상태'}</h4>
      <p>{deterministic?'자동 수정안 · 정적 근거 기반 · 외부 AI 전송·비용 없음':'AI 수정 제안 · 외부 Provider 사용'}</p>
      <p>{file.path} · 현재 {selected.startLine}행 · 기준 revision {selected.revision} · {selected.ruleId}</p>
      {selected.flowFindingId&&<p>{deterministic?'수정':'전송'} 범위: {selected.startLine}~{selected.startLine+selected.before.split('\n').length-1}행의 객체 응답 부분입니다. 파일 전체가 아닙니다.</p>}
      <p>{selected.explanation}</p>
      {!deterministic&&selected.state === 'APPROVAL_REQUIRED' && <>
        <p>전송 대상: 아래{selected.flowFindingId?' 객체 응답 코드':' 설정 한 줄'}와 Finding 규칙·파일 ID·행·내용 해시. 다른 파일과 주변 코드는 전송하지 않습니다.</p>
        <pre className="source-ai-code">{selected.before}</pre>
        <p>{selected.provider.name} / {selected.provider.model} · 저장소 밖 Provider로 전송합니다. 민감정보가 보이면 동의하지 마세요.</p>
        <label className="source-export-approval"><input type="checkbox" checked={consented} disabled={!!pending || dirty} onChange={e => setConsented(e.target.checked)} />이 코드 범위의 외부 전송과 유료 호출 가능성에 동의합니다.</label>
        <button type="button" className="primary-button" disabled={disabled || !!pending || dirty || !consented} onClick={generate}>동의한 코드로 AI 수정안 생성</button>
      </>}
      {selected.state === 'GENERATING' && <p role="status">코드를 변경하지 않고 제안을 생성하고 있습니다. 취소해도 이미 전송한 요청의 처리·요금 취소는 보증하지 않습니다.</p>}
      {selected.diff && <div className="source-diff"><h4>현재 수정본 → {deterministic?'자동 수정안':'AI 제안'}</h4><pre tabIndex={0}>{selected.diff}</pre></div>}
      {selected.verificationSteps.length > 0 && <><h4>수정 후 확인</h4><ul>{selected.verificationSteps.map((s,i) => <li key={i}>{s}</li>)}</ul></>}
      <ul>{selected.limitations.map((s,i) => <li key={i}>{s}</li>)}</ul>
      {selected.state === 'PROPOSED' && <><label className="source-export-approval"><input type="checkbox" checked={accepted} disabled={disabled || dirty || !!pending} onChange={e => setAccepted(e.target.checked)} />Diff와 미확인 조건을 검토했고 현재 작업 공간에만 적용하도록 승인합니다.</label>
        {selected.flowFindingId&&<label className="source-export-approval"><input type="checkbox" checked={compatibilityAccepted} disabled={disabled||dirty||!!pending} onChange={e=>setCompatibilityAccepted(e.target.checked)} />응답 필드 제거로 API 호환성이 달라질 수 있음을 확인했습니다.</label>}
        <button type="button" className="primary-button" disabled={disabled || dirty || !!pending || !accepted || (!!selected.flowFindingId&&!compatibilityAccepted)} onClick={apply}>{deterministic?'검토한 자동 수정안 적용':'검토한 AI 수정안 적용'}</button></>}
      {['APPROVAL_REQUIRED','GENERATING','PROPOSED','NEEDS_REVIEW'].includes(selected.state) && <button type="button" className="secondary-button" disabled={disabled} onClick={() => void reject()}>{selected.state === 'GENERATING' ? '생성 취소·거절' : '제안 거절'}</button>}
    </div>}
    {dirty && <p>저장하지 않은 편집이 있습니다. 제안 생성·적용 전에 직접 저장하거나 되돌려 주세요.</p>}
  </section>;
}
