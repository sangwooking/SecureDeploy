import type { ReactNode } from 'react';

/** Presentation only: evidence and advice remain separate, immutable server results. */
export function EvidenceSupportLayout({evidence,support,evidenceTitle='발견된 보안 문제',supportTitle='AI·수정 지원'}:{evidence:ReactNode;support:ReactNode;evidenceTitle?:string;supportTitle?:string}) {
 return <div className="evidence-support-layout">
  <section className="analysis-evidence"><header className="support-pane-heading"><span className="source-label">분석 근거</span><h3>{evidenceTitle}</h3></header>{evidence}</section>
  <section className="analysis-support"><header className="support-pane-heading"><span className="source-label source-label-advice">의견·수정 안내</span><h3>{supportTitle}</h3></header>{support}</section>
 </div>;
}
export function providerOriginLabel(origin?:string,name?:string) {
 return name==='TEMPLATE'?'근거 기반 템플릿 · AI 모델 미사용':origin==='OPENAI'?'OpenAI 모델 응답':origin==='MOCK'?'Mock 통제 응답 · 실제 모델 미검증':origin==='ARCHIVED_OPENAI'?'과거 OpenAI 검증 기록 · 새 호출 없음':'Provider 출처 미확인';
}
export function changeOriginLabel(origin?:string) {
 const labels:Record<string,string>={MANUAL:'사용자 수동 수정',DETERMINISTIC_APPROVED:'승인된 자동 수정 · 규칙 기반',MANUAL_AFTER_DETERMINISTIC:'자동 수정 적용 후 수동 변경 · 규칙 기반',AI_APPROVED:'승인된 AI 코드 수정',MANUAL_AFTER_AI:'AI 코드 수정 후 수동 변경',PACKAGE_MANAGER_APPROVED:'패키지 관리자 생성 · 사용자 승인'};
 return labels[origin??'']??'수정 출처 미기록';
}
export function AdvisoryItemCount({count}:{count:number}) {
 return <span className="inline-count advisory-item-count"><span>공지 항목</span><strong>{count}</strong></span>;
}
