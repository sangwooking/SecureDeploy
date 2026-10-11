import type { RemediationSnapshot, RiskFinding, RemediationGenerationStatus } from '../types/securityReview';

const labels: Record<RemediationGenerationStatus, string> = {
  GENERATED: 'AI 생성', TEMPLATE: '템플릿 가이드', UNAVAILABLE: '생성 불가', FAILED: '생성 실패', NOT_REQUESTED: '생성 대상 아님',
};

export function RemediationNotice({ snapshot }: { snapshot?: RemediationSnapshot | null }) {
  if (!snapshot) return <p className="remediation-notice">이 분석 이력에는 저장된 AI 해결 가이드가 없습니다. 재분석 시 생성됩니다.</p>;
  return <div className="remediation-notice" role="status">
    {snapshot.notices.map((notice, index) => <p key={index}>{notice}</p>)}
    {snapshot.omittedFindingCount > 0 && <p>생성 한도로 {snapshot.omittedFindingCount}개 Finding의 가이드는 생략되었습니다. 위험 평가에는 그대로 포함됩니다.</p>}
    {snapshot.usage && <p>해결 가이드 · {snapshot.usage.provider} · {snapshot.usage.totalTokens} tokens · 비용 추정 미산정</p>}
  </div>;
}

export function FindingRemediation({ finding, snapshot }: { finding?: RiskFinding; snapshot?: RemediationSnapshot | null }) {
  const item = snapshot?.findings.find(entry => entry.findingId === finding?.findingId);
  if (!item) return null;
  if (!item.advice) return <p className="remediation-notice">AI 해결 가이드: {labels[item.generationStatus]}. 기존 위험 평가는 유지됩니다.</p>;
  const advice = item.advice;
  return <details className="finding-remediation">
    <summary>AI 해결 가이드 <span>{labels[item.generationStatus]}</span></summary>
    <p className="remediation-notice">검토 후 적용할 수정 제안입니다. 탐지 신뢰도·우선순위·배포 판단은 변경하지 않습니다.</p>
    <h4>{advice.summary}</h4>
    <dl>
      <div><dt>왜 위험한가</dt><dd>{advice.whyItMatters}</dd></div>
      <div><dt>권장 수정</dt><dd>{advice.recommendedAction}</dd></div>
      {advice.codeExample && <div><dt>코드 예시</dt><dd><pre><code>{advice.codeExample}</code></pre></dd></div>}
      {advice.configurationExample && <div><dt>설정 예시</dt><dd><pre><code>{advice.configurationExample}</code></pre></dd></div>}
      <div><dt>수정 후 확인</dt><dd><ul>{advice.verificationSteps.map((step, index) => <li key={index}>{step}</li>)}</ul></dd></div>
      {advice.caution && <div><dt>주의사항</dt><dd>{advice.caution}</dd></div>}
    </dl>
    <p className="remediation-notice">수정안 신뢰도: {advice.remediationConfidence} (탐지 신뢰도와 별개)
      {' · '}{item.provider}{item.model ? ` / ${item.model}` : ''}{' · '}{item.promptVersion}
      {' · '}<time dateTime={item.generatedAt}>{new Date(item.generatedAt).toLocaleString('ko-KR')}</time></p>
  </details>;
}
