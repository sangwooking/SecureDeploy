import { useState } from 'react';
import type { CoverageLedger } from '../types/analysisCoverage';
import type { ScaResult, SemanticSnapshot } from '../types/securityReview';

const statuses: Record<string, string> = {
  COMPLETE: '완료', PARTIAL: '일부 확인', FAILED: '실패', UNAVAILABLE: '확인하지 못함',
  LIMIT_EXCEEDED: '제한 초과', SELECTED: '패턴 검사 입력', UNSUPPORTED: '미지원', EXCLUDED: '제외',
  DISABLED: '비활성', NO_MANIFEST: '지원 manifest 없음', NOT_APPLICABLE: '조회 대상 없음',
  UNKNOWN: '확인하지 못함', ROOT_DECLARED: '기본 최종 stage에 root 선언', NON_ROOT_DECLARED: '기본 최종 stage에 non-root 선언',
};
export function InspectionBoundaryNotice({ coverage }: { coverage?: CoverageLedger | null }) {
  const scope = coverage?.inspectionScope;
  const gaps = scope?.areas.filter(a => !['ROOT_DECLARED', 'NON_ROOT_DECLARED'].includes(a.status)) ?? [];
  return <div className="decision-disclaimer" aria-label="배포 판단의 검사 범위 한계">
    <strong>지원 범위의 판단이며, 전체 프로젝트 검사 완료를 뜻하지 않습니다.</strong>
    {!scope ? <p>이 이력에는 주요 영역별 검사 근거가 없습니다. 아래 파일별 범위 기록을 확인하세요. 과거 범위를 추측하지 않습니다.</p>
      : <>
        {gaps.length > 0 && <ul>{gaps.map(a => <li key={`${a.id}:${a.status}`}>
          {a.label} · {statuses[a.status] ?? a.status} ({a.observedFiles}개 관측)
        </li>)}</ul>}
        {!!scope.incompleteAnalyzers.length && <p>일부 완료·실패·미실행 분석이 있습니다. 아래 검사 범위의 분석기 상태를 확인하세요.</p>}
        {!scope.evidenceComplete && <p>제외 폴더 또는 목록 제한으로 범위 기록도 일부만 확보했습니다. 미표시 영역을 검사 완료로 해석하지 마세요.</p>}
        {!gaps.length && <p>기록된 범위 밖의 언어, 실제 실행 환경과 권한 검증까지 안전하다고 보증하지 않습니다.</p>}
      </>}
  </div>;
}
const reasons: Record<string, string> = {
  NO_SUPPORTED_ANALYZER: '지원하는 분석기가 없는 파일', DIRECTORY_POLICY: '산출물·외부 패키지 제외 정책',
  DIRECTORY_POLICY_SUBTREE_NOT_ENUMERATED: '제외 폴더 내부는 열거하지 않음',
  PATTERN_ANALYSIS_INPUT: '문자열·설정 패턴 검사. 언어 전체 의미 분석 아님',
  SYMLINK: '링크를 따라가지 않음', LFS_POINTER: 'LFS 실제 내용 미수집', SUBMODULE_NOT_ENUMERATED: '하위 저장소 미수집',
  TEXT_BUDGET: '텍스트 크기·파일 수·줄 수 제한', TEXT_READ_OR_ENCODING: '읽기 또는 인코딩 실패',
  FILE_READ: '파일 읽기 실패', STATIC_MANIFEST_PARSED: '정적 의존성 추출 완료',
  MANIFEST_SIZE_LIMIT: 'manifest 크기 제한', MANIFEST_COUNT_LIMIT: 'manifest 수 제한',
  UNSUPPORTED_OR_INVALID_MANIFEST: '미지원 형식 또는 손상된 manifest',
};
export function AnalysisCoverageSection({ coverage, sca, semantic }: {
  coverage?: CoverageLedger | null; sca?: ScaResult | null; semantic?: SemanticSnapshot | null;
}) {
  const [filter, setFilter] = useState('ALL');
  const [page, setPage] = useState(0);
  if (!coverage) return <section className="analysis-coverage-brief" aria-label="검사 범위">
    <h3>검사 범위</h3><p>이 이력에는 파일별 범위 기록이 없습니다. 과거에 검사하지 못한 영역을 추측하지 않습니다.</p>
  </section>;
  const entries = coverage.entries.filter(e => filter === 'ALL' || e.status === filter);
  const current = Math.min(page, Math.max(0, Math.ceil(entries.length / 20) - 1));
  return <section className="analysis-coverage-brief" aria-label="검사 범위">
    <h3>무엇을 검사했나요?</h3>
    <p>발견한 파일 {coverage.discoveredFiles}개 · 패턴 검사 입력 {coverage.selectedFiles}개 · 미지원 {coverage.unsupportedFiles}개 · 제외 {coverage.excludedFiles}개 · 실패 {coverage.failedFiles}개</p>
    <p>파일 수는 보안 검증 범위와 같지 않습니다. 패턴 검사를 마친 파일도 인증 흐름·실행 경로 전체를 검증한 것은 아닙니다.</p>
    {(coverage.unsupportedFiles > 0 || coverage.excludedFiles > 0 || !coverage.inventoryComplete) &&
      <p className="review-caution">검사하지 못한 영역이 있습니다. 배포 판단은 검사된 범위의 결과이며, 미지원·제외 영역의 안전 여부는 별도 확인이 필요합니다.</p>}
    {!coverage.inventoryComplete && <p>하위 저장소·제외 폴더 내부 또는 중단 이후 파일 수는 확인하지 못했습니다. 발견한 파일 수는 전체 저장소 파일 수가 아닐 수 있습니다.</p>}
    <details className="coverage-details"><summary>분석기와 파일별 범위 보기</summary>
      {coverage.inspectionScope && <><h4>주요 영역과 확인하지 못한 부분</h4>
        <ul className="coverage-file-list">{coverage.inspectionScope.areas.map(a => <li key={`${a.id}:${a.status}`}>
          <strong>{a.label} · {statuses[a.status] ?? a.status} · {a.observedFiles}개 관측</strong>
          <span>{a.limitation}</span>
          {a.examplePaths.map(path => <code key={path} className="finding-location">{path}</code>)}
        </li>)}</ul></>}
      <dl>{coverage.analyzers.map(a => <div key={a.analyzer}><dt>{a.analyzer} · {statuses[a.status] ?? a.status}</dt><dd>{a.scope}</dd></div>)}</dl>
      <p>AI Semantic: {semantic?.semanticReviewStatus === 'NOT_REQUESTED' ? '실행하지 않음 (후보 0건 또는 안전 판정 아님)' : semantic?.semanticReviewStatus ?? '저장된 기록 없음'}</p>
      <label className="finding-filter">파일 상태 <select value={filter} onChange={e => { setFilter(e.target.value); setPage(0); }}>
        <option value="ALL">전체</option>{['SELECTED', 'UNSUPPORTED', 'EXCLUDED', 'FAILED', 'LIMIT_EXCEEDED'].map(s => <option key={s} value={s}>{statuses[s]}</option>)}
      </select></label>
      <ul className="coverage-file-list">{entries.slice(current * 20, current * 20 + 20).map((e, i) => <li key={`${e.filePath}:${i}`}>
        <code className="finding-location">{e.filePath}</code><span>{statuses[e.status] ?? e.status} · {reasons[e.reason] ?? e.reason}</span>
      </li>)}</ul>
      {entries.length === 0 && <p>이 상태로 기록된 항목이 없습니다.</p>}
      {coverage.omittedEntries > 0 && <p>기록 크기 제한으로 경로 목록 {coverage.omittedEntries}건은 생략했습니다. 위 집계에는 포함됩니다.</p>}
      {entries.length > 20 && <nav className="finding-pagination" aria-label="범위 기록 페이지">
        <button type="button" disabled={current === 0} onClick={() => setPage(current - 1)}>이전</button>
        <span>{current + 1} / {Math.ceil(entries.length / 20)}</span>
        <button type="button" disabled={(current + 1) * 20 >= entries.length} onClick={() => setPage(current + 1)}>다음</button>
      </nav>}
      {!!sca?.manifests?.length && <><h4>의존성 파일 파싱</h4><ul className="coverage-file-list">{sca.manifests.map(m => <li key={m.filePath}>
        <code className="finding-location">{m.filePath}</code><span>{statuses[m.status] ?? m.status} · {reasons[m.reason] ?? m.reason}</span>
      </li>)}</ul></>}
    </details>
  </section>;
}
