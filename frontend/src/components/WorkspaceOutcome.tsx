import type { SecurityReviewResponse } from '../types/securityReview';
import { PatchDiff } from './PatchDiff';
import { changeOriginLabel } from './EvidenceSupportLayout';
import { summaryStateLabel } from './ReviewSummaryPanel';
export interface FileDifferenceView {path:string;patch:string;origin?:string}
export function WorkspaceDiffReview({files,heading=true}:{files:FileDifferenceView[];heading?:boolean}) {
 return <section className="workspace-diff-review" aria-label="수정 내용 확인">{heading&&<h3>수정 내용 확인</h3>}<p>실제 변경 파일의 Diff입니다. 출처가 기록되지 않은 경우 AI·자동 수정으로 추정하지 않습니다.</p>{files.map(f=><div className="source-diff" key={f.path}><h4>{f.path}</h4><p className="change-origin">{changeOriginLabel(f.origin)}</p><PatchDiff patch={f.patch||'변경 없음'}/></div>)}</section>;
}
export function WorkspaceComparisonOverview({original,modified}:{original:SecurityReviewResponse;modified:SecurityReviewResponse}) {
 const verified=modified.workspaceScan?.baselineVerified&&modified.workspaceScan.originalReviewId===original.reviewId;
 const comparable=verified&&original.sca?.status==='COMPLETE'&&modified.sca?.status==='COMPLETE'&&modified.comparison!=null&&!['UNAVAILABLE','NO_BASELINE'].includes(modified.comparison.status);
 return <section className="workspace-comparison-summary" aria-label="외부 라이브러리 공지 항목 비교"><h3>수정본 재검사</h3>
 {comparable?<><p>원본과 수정본에서 조회된 보안 공지·패키지·버전 항목입니다.</p><div className="comparison-pair"><div><span>원본 분석</span><strong>{original.sca!.dependencyVulnerabilities.length}</strong></div><span aria-hidden="true">→</span><div><span>수정본 분석</span><strong>{modified.sca!.dependencyVulnerabilities.length}</strong></div></div><p>고유 취약점 수·수정 작업 수가 아니며 공지 감소가 전체 안전성의 증명은 아닙니다.</p></>:<p>원본 동일성·공지 조회 또는 비교 근거가 부족해 자동으로 해결을 판단하지 않습니다.</p>}
 <div className="comparison-boundary"><h4>남아 있는 확인 사항</h4><p>{summaryStateLabel(modified.coverage?.status??'NOT_RECORDED')}</p><p>정상 기능·API 호환성은 아직 확인하지 않았어요. 전체 웹사이트 안전성도 미검증입니다.</p></div>
 <details><summary>원본 상태값과 검증 범위</summary><p>{modified.coverage?.status??'NOT_RECORDED'} · NOT_VERIFIED · REVIEW_REQUIRED</p><p>원본 Review {original.reviewId} · 수정본 Review {modified.reviewId} · 비교 상태 {modified.comparison?.status??'NOT_RECORDED'}</p></details>
 </section>;
}
