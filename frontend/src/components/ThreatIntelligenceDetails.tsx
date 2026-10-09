import type { DependencyVulnerability, ThreatIntelligenceSnapshot, ThreatLookupStatus } from '../types/securityReview';

const lookupLabels: Record<ThreatLookupStatus, string> = {
  AVAILABLE: '조회 완료', NOT_FOUND: '데이터 미수록', UNAVAILABLE: '조회 불가',
  STALE: '최신 확인 필요', NOT_REQUESTED: '조회하지 않음',
};
function probability(value: number | null | undefined) {
  return value != null && Number.isFinite(value) && value >= 0 && value <= 1;
}
function timestamp(value: string | null | undefined) {
  if (!value) return '미확인';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '미확인' : date.toISOString().slice(0, 19).replace('T', ' ') + ' UTC';
}

export function ThreatIntelligenceDetails({ finding, snapshot }: {
  finding: DependencyVulnerability; snapshot?: ThreatIntelligenceSnapshot | null;
}) {
  const cves = [...new Set([finding.osvId, ...finding.aliases].map(id => id.toUpperCase())
    .filter(id => /^CVE-\d{4}-\d{4,19}$/.test(id)))];
  if (cves.length === 0) return <p className="risk-unavailable">CVE 연결 없음 · EPSS/KEV 조회 대상 아님</p>;
  if (!snapshot) return <p className="risk-unavailable">저장된 Threat Intelligence가 없습니다. 재분석이 필요합니다.</p>;
  return <details className="threat-intelligence">
    <summary>Threat Intelligence · EPSS / KEV</summary>
    <p>EPSS score는 향후 30일간 해당 CVE의 악용 활동이 관측될 가능성 예측값입니다. Percentile은 다른 CVE 대비 상대 위치이며, 이 프로젝트의 해킹 확률이 아닙니다.</p>
    <p>KEV는 실제 공격에서 악용된 사실의 등재 여부입니다. 미수록도 안전을 뜻하지 않습니다.</p>
    {cves.map(cve => {
      const data = snapshot.cves[cve];
      const e = data?.epss;
      const k = data?.kev;
      const known = k?.knownExploited === true ? 'YES · 실제 악용 확인'
        : k?.status === 'AVAILABLE' && k.knownExploited === false ? 'NO · 조회한 catalog에 미수록' : '미확인';
      return <div className="threat-cve" key={cve}>
        <strong>{cve}</strong>
        <dl className="sca-finding-details threat-facts">
          <div><dt>EPSS Score (0–1)</dt><dd>{probability(e?.score) ? e!.score!.toFixed(5) : '미확인'}</dd></div>
          <div><dt>EPSS Percentile</dt><dd>{probability(e?.percentile) ? `${(e!.percentile! * 100).toFixed(2)} 백분위` : '미확인'}</dd></div>
          <div><dt>EPSS 상태 / 데이터 날짜</dt><dd>{e ? lookupLabels[e.status] : '미조회'} · {e?.date ?? '미확인'}</dd></div>
          <div><dt>Known Exploited</dt><dd>{known}</dd></div>
          <div><dt>KEV 조회 상태</dt><dd>{k ? lookupLabels[k.status] : '미조회'}</dd></div>
          {k?.dateAdded && <div><dt>KEV 등재일</dt><dd>{k.dateAdded}</dd></div>}
          {k?.requiredAction && <div className="threat-wide"><dt>CISA 권고 조치</dt><dd>{k.requiredAction}</dd></div>}
          {k?.dueDate && <div><dt title="CISA catalog상의 대상 기관 조치 기한이며 프로젝트의 자동 마감일은 아닙니다.">CISA 조치 기한</dt><dd>{k.dueDate}</dd></div>}
          {k?.knownRansomwareCampaignUse && <div><dt>랜섬웨어 악용 정보</dt><dd>{k.knownRansomwareCampaignUse}</dd></div>}
          <div className="threat-wide"><dt>KEV catalog 갱신</dt><dd>{k?.catalogVersion ?? '미확인'} · {timestamp(k?.catalogReleasedAt)}</dd></div>
          <div className="threat-wide"><dt>EPSS / KEV 수집 시각</dt><dd>{timestamp(e?.fetchedAt)} / {timestamp(k?.fetchedAt)}</dd></div>
        </dl>
      </div>;
    })}
    <p>분석 당시 snapshot · {timestamp(snapshot.observedAt)}</p>
    <p><a href="https://www.first.org/epss/" target="_blank" rel="noreferrer">FIRST EPSS</a> · <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noreferrer">CISA KEV</a></p>
  </details>;
}
