import type { SecurityReviewResponse } from '../types/securityReview';
import type { ReactNode } from 'react';
import { deploymentLabels } from './reviewPresentation';
import { inspectionLabel, securityTerms } from './uiLanguage';

export const summaryStateLabel = inspectionLabel;
const observationLabels: Record<string,string> = {
  SQL_NOT_RUN:'정책 SQL 분석 미실행', SQL_LIMIT_EXCEEDED:'정책 SQL 분석 자원 제한', SQL_PARSE_FAILED:'정책 SQL 파싱 실패',
  AST_PARSE_FAILED:'구문 파싱 실패', AST_LIMIT_EXCEEDED:'구문 분석 자원 제한',
  FLOW_NOT_SUPPORTED:'코드 흐름 미지원', FLOW_NOT_RUN:'코드 흐름 미실행',
};
const recorded = (value?: number | null) => value == null ? '미기록' : `${value}건`;

export function ReviewSummaryPanel({ result, actions, children }: { result: SecurityReviewResponse; actions?: ReactNode; children?: ReactNode }) {
  const summary=result.resultSummary?.schemaVersion===1?result.resultSummary:null;
  const policy=result.riskAssessment?.prioritizedDeploymentAssessment;
  const coverage=summary?.coverageStatus??result.coverage?.status??'NOT_RECORDED';
  const sca=summary?.scaStatus??result.sca?.status??'NOT_RECORDED';
  const semantic=summary?.semanticStatus??'NOT_RECORDED';
  const blocked=policy==='BLOCKED'||(result.riskAssessment?.prioritySummary.BLOCKING??0)>0;
  // Missing summary is historical absence, never a client-side replacement risk policy.
  const title=blocked?'반드시 처리할 문제부터 확인해 주세요':!summary?'이전 검사 결과를 확인해 주세요'
    :policy==='REVIEW_REQUIRED'?'배포 전에 직접 확인할 부분이 있어요'
    :policy==='READY_WITH_WARNINGS'?'수정하면 좋을 항목이 있어요':'확인한 결과와 검사 범위를 함께 살펴보세요';
  const omissions=summary?.analyzers.flatMap(a=>Object.entries(a.observations)
    .filter(([key,count])=>key in observationLabels&&count>0)
    .map(([key,count])=>({id:`${a.analyzer}:${key}`,label:observationLabels[key],count,analyzer:a.analyzer})))??[];
  return <div className="review-summary-panel" aria-label="분석 결과 통합 안내">
    <p className="summary-kicker">이번 검사 결과</p>
    <h2>{title}</h2>
    <p className="summary-lead">{blocked?'저장된 배포 정책에서 수정이 필요한 문제를 찾았어요. 아래 문제부터 확인해 주세요.'
      :policy==='REVIEW_REQUIRED'?'코드의 사용 방식이나 아직 확인하지 못한 정보가 있어요. 문제의 근거를 확인한 뒤 배포를 판단해 주세요.'
      :'아래 내용은 확인한 코드와 알려진 보안 정보에 대한 결과예요. 웹사이트 전체의 안전을 보증하지는 않아요.'}</p>
    {!summary&&<p>새 요약 기록이 없는 이력입니다. 저장된 경고와 정책 판단을 유지하며, 과거 검사 범위나 구조 후보를 추측해서 채우지 않습니다.</p>}
    {actions}
    {children}
    <dl className="summary-facts">
      <div><dt>저장된 배포 판단</dt><dd>{policy?deploymentLabels[policy]:'판단 기록 없음'}</dd><small>실제 배포 승인과는 달라요.</small></div>
      <div><dt>{securityTerms.score}</dt><dd>{result.securityScore} / 100</dd><small>전체 안전 점수가 아닙니다. 별도 검토 후보와 미검사 범위는 포함하지 않아요.</small></div>
      <div><dt>검사 범위</dt><dd>{summaryStateLabel(coverage)}</dd><small>파일을 읽은 것과 보안 동작을 확인한 것은 달라요.</small></div>
      <div><dt>{securityTerms.libraries}</dt><dd>{summaryStateLabel(sca)}</dd><small>알려진 보안 공지를 조회한 결과예요.</small></div>
    </dl>
    <p className="review-caution summary-boundary" role="note"><strong>추가로 확인해 주세요.</strong>{' '}
      {coverage==='PARTIAL'?'일부 코드와 동작은 확인하지 못했어요. ':coverage==='FAILED'?'검사를 완료하지 못했어요. ':''}
      실제 배포 환경과 사용자 접근권한은 별도 확인이 필요해요. 100점도 전체 안전을 뜻하지 않습니다.</p>
    <p className="summary-inspection-status">AI 추가 검토 · {summaryStateLabel(semantic)}.
      {summary&&summary.unresolvedDependencies!==0&&<> 버전 미확정 {recorded(summary.unresolvedDependencies)}.</>}
    </p>
    {(summary?.authContextObserved||summary?.rlsDeclarationsObserved)&&<p className="review-caution">
      {summary.authContextObserved&&'인증 관련 호출·선언 관찰은 로그인 성공이나 리소스 소유권 검증을 뜻하지 않습니다. '}
      {summary.rlsDeclarationsObserved&&'RLS SQL은 저장소 선언이며 운영 DB 적용과 실제 역할은 미확인입니다.'}
    </p>}
    <dl className="summary-candidates">
      <div><dt>코드 흐름 검토 후보</dt><dd>{recorded(summary?.flowCandidates)}</dd></div>
      <div><dt>설정·RLS 선언 검토 후보</dt><dd>{recorded(summary?.declarationCandidates)}</dd></div>
      <div><dt>AI 추가 후보</dt><dd>{recorded(summary?.aiCandidates)}</dd></div>
    </dl>
    {!!omissions.length && <p className="review-caution" role="note">완료하지 못한 검사: {omissions.map(o=>`${o.label} ${o.count}개`).join(' · ')}. 겹치는 분석기 기록이며 전체 파일 수가 아닙니다.</p>}
    {!!summary?.importantRuleSignals && <p className="review-caution">HIGH/CRITICAL 규칙 경고 {summary.importantRuleSignals}건. 실제 공격 여부는 별도 확인이 필요합니다.</p>}
    <details className="summary-detail"><summary>분석 근거와 확인하지 못한 범위</summary>
    <dl className="technical-grid"><div><dt>배포 정책 · 버전</dt><dd><code>{policy??'NOT_RECORDED'}</code> · {result.riskAssessment?.policyVersion??'미기록'}</dd></div>
      <div><dt>검사 범위 · 외부 조회 · AI 상태</dt><dd><code>{coverage}</code> · <code>{sca}</code> · <code>{semantic}</code></dd></div></dl>
    {summary&&<p>{summary.title}</p>}
    {summary&&<p>{summary.reason}</p>}
    <p>미발견이 완전한 안전을 뜻하지 않으며, 구조·AI 후보는 기존 점수와 정책 판단에 합산하지 않습니다. 미기록은 0건이나 안전 판정이 아닙니다.</p>
    <ul className="summary-boundaries">
      {!!summary?.importantRuleSignals&&<li><strong>심각도 HIGH/CRITICAL 규칙 경고: </strong>{summary.importantRuleSignals}건. 실제 공격 여부와 처리 우선순위는 별도 근거를 확인하세요.</li>}
      <li><strong>라이브러리 외부 조회: </strong>{summaryStateLabel(sca)} · <code>{sca}</code>
        {summary&&<> · 조회 완료 {recorded(summary.dependenciesAnalyzed)} · 버전 미확정 {recorded(summary.unresolvedDependencies)}</>}
        . 공개 패키지명·정확한 버전 기준의 알려진 보안 공지이며 실제 실행 경로나 전체 안전을 보증하지 않습니다.</li>
      <li><strong>운영 환경: </strong>실제 공격·배포 상태·사용자 권한은 검증하지 않았습니다.
        </li>
      {summary&&<li><strong>위험 계산: </strong>{summaryStateLabel(summary.riskCalculationStatus)} · <code>{summary.riskCalculationStatus??'NOT_RECORDED'}</code>. 계산 완료와 프로젝트 보안 검사 완료는 다릅니다.</li>}
      {summary&&<li><strong>AI 검토: </strong>{summaryStateLabel(semantic)} · <code>{semantic}</code>. 미실행은 후보 없음이나 안전 확인이 아닙니다.</li>}
    </ul>
    {!!omissions.length&&<p>위 수는 분석기별 기록입니다. 서로 겹칠 수 있으며 프로젝트 전체 미검사 파일 수로 합산하지 않습니다.</p>}
    {summary&&<>
      <dl>
        <div><dt>요약 버전 · 안내</dt><dd>{summary.schemaVersion} · {summary.interpretationVersion??'NOT_RECORDED'} · <code>{summary.guidance??'NOT_RECORDED'}</code></dd></div>
        <div><dt>요약에 저장된 정책 · 버전 · 필수 처리</dt><dd><code>{summary.policyAssessment??'NOT_RECORDED'}</code> · {summary.policyVersion??'NOT_RECORDED'} · {recorded(summary.blockingCount)}</dd></div>
        <div><dt>요약 참고 점수 · 범위 · 이전 배포 표시</dt><dd>{summary.referenceScore??'미기록'} · <code>{summary.scoreScope??'NOT_RECORDED'}</code> · {summary.legacyDeploymentStatus??'미기록'}</dd></div>
        <div><dt>발견 파일 · 규칙 입력 파일 · 목록 완전성</dt><dd>{recorded(summary.discoveredFiles)} · {recorded(summary.patternInputFiles)} · <code>{summary.inventoryComplete==null?'NOT_RECORDED':String(summary.inventoryComplete)}</code></dd></div>
        <div><dt>구조 비교 · 운영 검증</dt><dd><code>{summary.structuralComparison??'NOT_RECORDED'}</code> · <code>{summary.runtimeVerification??'NOT_RECORDED'}</code></dd></div>
      </dl>
      <ul>{summary.analyzers.map((analyzer,index)=><li key={`${analyzer.analyzer}:${index}`}>
        <strong className="summary-analyzer">{analyzer.analyzer}</strong>: {summaryStateLabel(analyzer.status)} · <code>{analyzer.status??'NOT_RECORDED'}</code>
        <ul>{Object.entries(analyzer.observations).map(([key,count])=><li key={key}>{observationLabels[key]??'분석기 기록'} · <code>{key}</code>: {count}개 기록</li>)}</ul>
      </li>)}</ul>
      {!!summary.limitations?.length&&<ul>{summary.limitations.map((limitation,index)=><li key={index}>{limitation}</li>)}</ul>}
    </>}
    </details>
  </div>;
}
