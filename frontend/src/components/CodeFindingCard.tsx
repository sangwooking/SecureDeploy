import {ProblemRepairGuide,repairGuide} from './ProblemRepairGuide';
import { EvidenceSupportLayout } from './EvidenceSupportLayout';
import type { RemediationSnapshot, RiskFinding, Vulnerability, VulnerabilityStatus } from '../types/securityReview';
import { FindingRemediation } from './FindingRemediation';
import { codeExplanation, priorityLabels } from './reviewPresentation';
import { findingGuidance, needsVerification } from './findingGuidance';
import { severityLabels } from './uiLanguage';

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
  const impact=v.ruleId==='DEBUG_ENABLED'?'디버그 로그와 개발 진단 정보가 줄어들 수 있습니다. 운영에 필요한 관측 수단을 확인하세요.':v.ruleId==='STACKTRACE_EXPOSURE'?'오류 응답 형식과 장애 진단 방식이 달라질 수 있습니다. 내부 로그와 클라이언트 처리를 확인하세요.':v.ruleId==='INSECURE_COOKIE'?'HTTPS 연결과 브라우저의 쿠키 전달·로그인 유지 동작을 확인하세요.':v.ruleId==='HARDCODED_SECRET'?'환경변수 주입과 기존 키 교체가 필요할 수 있습니다. 배포 설정과 관련 연동을 확인하세요.':'정상 입력과 거부해야 할 입력을 함께 확인하고 기존 기능·출력 형식이 유지되는지 테스트하세요.';
  return <article className="vulnerability-item action-finding">
    <EvidenceSupportLayout evidence={<>
    <div className="vulnerability-header">
      <span className={`risk-badge risk-${finding?.priority.toLowerCase() ?? 'review_required'}`}>
        {finding ? priorityLabels[finding.priority] : '우선순위 미평가'}
      </span>
      <span className="status-badge">{statusLabels[status]}</span>
    </div>
    <p>{repairGuide(v.ruleId,v).summary}</p><p className="finding-origin">규칙 경고 · 코드에서 확인한 단서 · 영향 수준 {severityLabels[v.severity]}</p>
    <h3>{needsReview ? guidance.summary : codeExplanation(v).title}</h3>
    <p className="finding-location"><strong>확인할 파일</strong> <code>{v.filePath}</code> · {v.line}행</p>
    <h4>어디가 문제인가요?</h4>{v.evidence?<pre className="finding-source-code">{v.evidence}</pre>:<p>저장된 코드 조각이 없습니다. 작업 공간에서 원본을 확인하세요.</p>}
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
      <p>메모는 상태를 변경할 때 함께 저장됩니다. 직접 기록한 상태이며, 수정본 재검사나 해결 검증을 대신하지는 않아요.</p>
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
    </>} support={<><ProblemRepairGuide rule={v.ruleId} v={v}/>
    {onEditFile&&<button className="primary-button" type="button" onClick={()=>onEditFile(v.filePath)}>이 문제 수정하기</button>}
    <p>기능 영향: {impact}</p><details><summary>저장된 AI 수정 설명</summary><FindingRemediation finding={finding} snapshot={remediation} vulnerability={v} />
</details><p>수정 적용 후 관련 기능과 분석 범위를 다시 확인하세요. 안전성을 입증하지 못한 부분은 검토 필요로 유지합니다.</p></>} />
  </article>;
}
