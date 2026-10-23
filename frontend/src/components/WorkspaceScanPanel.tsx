import { useEffect, useState } from 'react';
import { loadWorkspaceScan, startWorkspaceScan } from '../api/editingApi';
import type { EditingWorkspace, WorkspaceScan } from '../api/editingApi';
import { fetchReviewDetail } from '../api/securityReviewApi';
import type { SecurityReviewResponse } from '../types/securityReview';
import { ReviewProgressPanel } from './ReviewProgressPanel';
import { ReviewSummaryPanel, summaryStateLabel } from './ReviewSummaryPanel';

export function WorkspaceScanPanel({ workspace, original, disabled }: {
  workspace: EditingWorkspace; original: SecurityReviewResponse; disabled: boolean;
}) {
  const key = `securedeploy.editing.scan.${workspace.id}`;
  const [scan, setScan] = useState<WorkspaceScan | null>(null);
  const [result, setResult] = useState<SecurityReviewResponse | null>(null);
  const [approved, setApproved] = useState(false), [starting, setStarting] = useState(false), [error, setError] = useState('');
  useEffect(() => { setApproved(false); }, [workspace.revision]);
  useEffect(() => {
    let active = true, timer: ReturnType<typeof setTimeout>;
    const poll = async (id: string) => {
      try {
        const next = await loadWorkspaceScan(id);
        if (!active) return;
        setScan(next);
        if (next.state === 'RUNNING') timer = setTimeout(() => void poll(id), 1500);
        else if (next.state === 'SUCCEEDED' && next.reviewId) {
          const saved = await fetchReviewDetail(next.reviewId);
          if (active) setResult(saved);
        }
      } catch (e) { if (active) setError(e instanceof Error ? e.message : '검사 상태를 확인하지 못했습니다.'); }
    };
    const id = scan?.id ?? sessionStorage.getItem(key);
    if (id) void poll(id);
    return () => { active = false; clearTimeout(timer); };
  }, [key, scan?.id]);
  const start = async () => {
    if (starting || disabled || !approved || scan?.state === 'RUNNING') return;
    setStarting(true); setError('');
    try {
      const next = await startWorkspaceScan(workspace);
      sessionStorage.setItem(key, next.id); setResult(null); setScan(next); setApproved(false);
      if (next.state === 'SUCCEEDED' && next.reviewId) setResult(await fetchReviewDetail(next.reviewId));
    } catch (e) { setError(e instanceof Error ? e.message : '수정본 검사를 시작하지 못했습니다.'); }
    finally { setStarting(false); }
  };
  return <section className="workspace-scan" aria-label="수정본 보안 재검사">
    <h3>수정본 다시 검사</h3>
    {workspace.identityStatus === 'UNVERIFIED_REUPLOAD' && <p role="note">원본 일치 미검증 ZIP: 별도 프로젝트의 새 기준 검사로 저장합니다. 과거 Review의 경고를 해결 처리하지 않습니다.</p>}
    <details className="scan-consent" open={!result}><summary>검사 revision·외부 조회 동의</summary>
    <p>저장된 revision {workspace.revision} 전체를 STANDARD로 검사합니다. 편집은 계속할 수 있으며 실행 중인 검사 입력은 바뀌지 않습니다.</p>
    <label><input type="checkbox" checked={approved} disabled={disabled || starting || scan?.state === 'RUNNING'} onChange={e => setApproved(e.target.checked)} />
      revision {workspace.revision}의 변경 {workspace.changedFileIds.length}개를 검사하며, 패키지명·생태계·확정 버전의 OSV 조회와 공개 취약점 식별자의 EPSS/KEV 조회에 동의합니다. 유료 AI는 호출하지 않습니다.</label>
    <button type="button" className="primary-button" disabled={disabled || !approved || starting || scan?.state === 'RUNNING'} onClick={() => void start()}>
      {starting || scan?.state === 'RUNNING' ? '수정본 검사 중...' : '수정본 다시 검사'}</button>
    </details>
    {error && <p role="alert" className="error-message">{error}</p>}
    {scan && <div aria-live="polite"><p>검사 revision {scan.revision} · {scan.message}</p>
      {scan.revision !== workspace.revision && <p role="status">현재 revision {workspace.revision}은 이 검사에 포함되지 않았습니다. 최신 수정본은 아직 재검사되지 않았습니다.</p>}
      <details><summary>검사 입력 근거</summary><p className="source-revision">입력 해시: {scan.inputHash}</p><p>원본 Review {original.reviewId} · 검사 시점 {new Date(scan.capturedAt).toLocaleString()}</p></details>
    </div>}
    {result && <>
      <div className="scan-result-overview" aria-label="수정본 결과 요약">
      <h4>수정본 Review {result.reviewId} · 원본 Review {original.reviewId}</h4>
      <p>참고 점수 {original.securityScore} → {result.securityScore} · 검사 범위 {summaryStateLabel(original.coverage?.status ?? 'NOT_RECORDED')} → {summaryStateLabel(result.coverage?.status ?? 'NOT_RECORDED')}</p>
      <p>구조 검토 후보: 코드 흐름 {original.resultSummary?.flowCandidates ?? '미기록'} → {result.resultSummary?.flowCandidates ?? '미기록'}, 설정·정책 {original.resultSummary?.declarationCandidates ?? '미기록'} → {result.resultSummary?.declarationCandidates ?? '미기록'} · NOT_COMPARED</p>
      <p>후보 수의 변화는 관찰 결과이며, 실제 취약점 해결 판정이 아닙니다.</p>
      </div>
      {result.projectId && <a href={`#/projects/${result.projectId}/findings?review=${result.reviewId}`}>저장된 수정본 결과와 History 열기</a>}
      <details className="saved-review-summary"><summary>수정본의 전체 분석 안내</summary><ReviewSummaryPanel result={result} /></details>
      <ReviewProgressPanel result={result} />
    </>}
  </section>;
}
