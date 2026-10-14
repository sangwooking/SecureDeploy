import type { RemediationSnapshot, RiskFinding, RemediationGenerationStatus } from '../types/securityReview';

const labels: Record<RemediationGenerationStatus, string> = {
  GENERATED: 'AI 생성', TEMPLATE: '템플릿 가이드', UNAVAILABLE: '생성 불가', FAILED: '생성 실패', NOT_REQUESTED: '생성 대상 아님',
};

export function RemediationNotice({ snapshot }: { snapshot?: RemediationSnapshot | null }) {
  if (!snapshot) return <p className="remediation-notice">이 분석 이력에는 저장된 해결 방법이 없습니다. 각 문제의 권장 조치를 참고하거나 재분석하세요.</p>;
  return <div className="remediation-notice" role="status">
    {snapshot.omittedFindingCount > 0 && <p>생성 한도로 {snapshot.omittedFindingCount}개 문제의 해결 방법이 생략되었습니다. 위험 평가에는 그대로 포함됩니다.</p>}
    <details><summary>해결 방법 생성 기록</summary>
      {snapshot.notices.map((notice, index) => <p key={index}>{notice}</p>)}
      {snapshot.usage && <p>{snapshot.usage.provider} · {snapshot.usage.totalTokens} tokens · 비용 추정 미산정</p>}
    </details>
  </div>;
}

export function FindingRemediation({ finding, snapshot }: { finding?: RiskFinding; snapshot?: RemediationSnapshot | null }) {
  const item = snapshot?.findings.find(entry => entry.findingId === finding?.findingId);
  if (!item) return null;
  if (!item.advice) return <p className="remediation-notice">AI 해결 가이드: {labels[item.generationStatus]}. 기존 위험 평가는 유지됩니다.</p>;
  const advice = item.advice;
  return <details className="finding-remediation">
    <summary>수정 방법 자세히 보기 <span>{labels[item.generationStatus]}</span></summary>
    <p className="remediation-notice">검토 후 적용할 수정 제안입니다. 탐지 신뢰도·우선순위·배포 판단은 변경하지 않습니다.</p>
    <h4>이게 어떤 문제인가요?</h4><p>{advice.summary}</p>
    <dl>
      <div><dt>왜 위험한가요?</dt><dd>{advice.whyItMatters}</dd></div>
      <div><dt>무엇을 수정해야 하나요?</dt><dd>{advice.recommendedAction}</dd></div>
      {advice.codeExample && <div><dt>코드 예시</dt><dd><pre><code>{advice.codeExample}</code></pre></dd></div>}
      {advice.configurationExample && <div><dt>설정 예시</dt><dd><pre><code>{advice.configurationExample}</code></pre></dd></div>}
      <div><dt>수정 후 무엇을 확인하나요?</dt><dd><ul>{advice.verificationSteps.map((step, index) => <li key={index}>{step}</li>)}</ul></dd></div>
      {advice.caution && <div><dt>주의사항</dt><dd>{advice.caution}</dd></div>}
    </dl>
    <details className="technical-details"><summary>수정안 기술 정보</summary><p className="remediation-notice">수정안 신뢰도: {advice.remediationConfidence} (탐지 신뢰도와 별개)
      {' · '}{item.provider}{item.model ? ` / ${item.model}` : ''}{' · '}{item.promptVersion}
      {' · '}<time dateTime={item.generatedAt}>{new Date(item.generatedAt).toLocaleString('ko-KR')}</time></p></details>
  </details>;
}
