import type { RemediationSnapshot, RiskFinding, Vulnerability, VulnerabilityStatus } from '../types/securityReview';
import { FindingRemediation } from './FindingRemediation';
import { codeExplanation, priorityLabels } from './reviewPresentation';
import { findingGuidance, needsVerification } from './findingGuidance';

const statusLabels: Record<VulnerabilityStatus, string> = {
  UNCHECKED: '미확인', ACKNOWLEDGED: '확인 완료', IN_PROGRESS: '수정 중', RESOLVED: '수정 완료', IGNORED: '무시',
};
export interface FindingStatusActions {
  updatingId: number | null;
  comments: Record<number, string>;
  onComment: (id: number, comment: string) => void;
  onStatus: (vulnerability: Vulnerability, status: VulnerabilityStatus) => void;
}

export function CodeFindingCard({ vulnerability: v, finding, remediation, statusActions, onEditFile }: {
  vulnerability: Vulnerability; finding?: RiskFinding; remediation?: RemediationSnapshot | null;
  statusActions: FindingStatusActions;
  onEditFile?: (path: string) => void;
}) {
  const id = v.vulnerabilityId;
  const status = v.status ?? 'UNCHECKED';
  const disabled = id == null || statusActions.updatingId === id;
  const needsReview = needsVerification(finding, v);
  const guidance = findingGuidance(finding, v);
  return <article className="vulnerability-item action-finding">
    <div className="vulnerability-header">
      <span className={`risk-badge risk-${finding?.priority.toLowerCase() ?? 'review_required'}`}>
        {finding ? priorityLabels[finding.priority] : '우선순위 미평가'}
      </span>
      <span className="status-badge">{statusLabels[status]}</span>
    </div>
    <p className="finding-origin">규칙 경고 · 정적 탐지 근거 · 심각도 {v.severity}</p>
    <h3>{needsReview ? guidance.summary : codeExplanation(v).title}</h3>
    <p className="finding-location"><strong>확인할 파일</strong> <code>{v.filePath}</code> · {v.line}행</p>
    {needsReview && <p className="review-caution">실제 사용 방식과 주변 코드에 따라 위험이 달라질 수 있습니다. 먼저 해당 상황인지 확인하세요.</p>}
    <h4>{needsReview ? '내가 확인할 일' : '내가 해야 할 일'}</h4>
    <p>{needsReview ? guidance.steps[0] : guidance.action}</p>
    {onEditFile && <button className="secondary-button" type="button" onClick={()=>onEditFile(v.filePath)}>이 파일 수정하기</button>}
    <FindingRemediation finding={finding} snapshot={remediation} vulnerability={v} />
    <details className="action-details"><summary>진행 상태와 메모</summary>
      <div className="status-manager">
        <label><span>상태</span><select aria-label="상태" value={status} disabled={disabled}
          onChange={event => statusActions.onStatus(v, event.target.value as VulnerabilityStatus)}>
          {Object.entries(statusLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select></label>
        <label><span>메모</span><input type="text" disabled={disabled} placeholder="예: 다음 배포에서 수정 예정"
          value={id != null ? statusActions.comments[id] ?? v.statusComment ?? '' : v.statusComment ?? ''}
          onChange={event => id != null && statusActions.onComment(id, event.target.value)} /></label>
        {id != null && statusActions.updatingId === id && <span role="status">저장 중...</span>}
      </div>
      <p>메모는 상태를 변경할 때 함께 저장됩니다.</p>
    </details>
    <details className="technical-details"><summary>기술 정보 보기</summary>
      <p className="finding-location"><strong>위치</strong> <code>{v.filePath}</code> <span className="finding-line">{v.line}행</span></p>
      <p>{v.message}</p>
      <p>{v.recommendation}</p>
      {finding && <p>{finding.priorityReason}</p>}
      {v.analysisNote?.trim() && <><h4>판단 근거</h4><p>{v.analysisNote}</p></>}
      <dl className="technical-grid">
        <div><dt>Rule ID</dt><dd>{v.ruleId}</dd></div>
        <div><dt>Severity</dt><dd>{v.severity}</dd></div>
        <div><dt>Category</dt><dd>{v.category}</dd></div>
        <div><dt>Confidence · 신뢰도</dt><dd>{v.confidence ?? '정보 없음'}</dd></div>
        <div><dt>False Positive Risk · 오탐 가능성</dt><dd>{v.falsePositiveRisk ?? '정보 없음'}</dd></div>
        {finding && <div><dt>Priority / Reason code</dt><dd>{finding.priority} / {finding.reasonCode}</dd></div>}
      </dl>
      <p>신뢰도는 규칙이 인식한 패턴·구문에 대한 확신입니다. HIGH라도 외부 입력 연결이나 실제 공격 성공을 입증하지 않습니다. 심각도는 영향 수준이며 오탐 가능성과 별개입니다. 보호 처리와 실행 조건을 함께 확인하세요.</p>
      {v.evidence && <div className="evidence-block"><span>Evidence (API 제공 값)</span><code>{v.evidence}</code></div>}
    </details>
  </article>;
}
