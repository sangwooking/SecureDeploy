import type { WorkspaceResponse, WorkspaceProject } from '../types/workspace';
import type { ReviewHistoryResponse, ProgressAssessment } from '../types/securityReview';
import { deploymentLabels } from './reviewPresentation';
import { projectLink } from './workspaceRoute';

export function reviewStatus(review?: ReviewHistoryResponse | null): string {
  return !review ? '분석 결과 없음' : review.riskSummary ? deploymentLabels[review.riskSummary.deploymentAssessment] : '위험 평가 미저장';
}
export function dateLabel(date?: string | null) { return date ? new Date(date).toLocaleString('ko-KR') : '아직 분석하지 않음'; }

export function PriorityCounts({ assessment }: { assessment?: ProgressAssessment | null }) {
  return <dl className="workspace-counts">
    <div><dt>반드시 처리</dt><dd>{assessment?.prioritySummary.BLOCKING ?? '미평가'}</dd></div>
    <div><dt>배포 전 직접 확인</dt><dd>{assessment?.prioritySummary.REVIEW_REQUIRED ?? '미평가'}</dd></div>
    <div><dt>수정 권장</dt><dd>{assessment?.prioritySummary.SHOULD_FIX ?? '미평가'}</dd></div>
  </dl>;
}

export function ProgressBrief({ progress }: { progress: WorkspaceProject['latestProgress'] }) {
  if (!progress || progress.status === 'NO_BASELINE') return <p>비교할 이전 분석이 없습니다.</p>;
  if (progress.status === 'UNAVAILABLE') return <p>변화 확인 불가 · {progress.message}</p>;
  return <div className="progress-brief"><p>
    해결됨 {progress.counts.RESOLVED} · 남아 있음 {progress.counts.REMAINING} · 새로 발견 {progress.counts.NEW}
    {' · '}변경됨 {progress.counts.CHANGED} · 확인 불가 {progress.counts.UNAVAILABLE}
  </p>{progress.status === 'PARTIAL' && <p>일부 범위는 비교하지 못했습니다. 확인 불가는 해결로 처리하지 않습니다.</p>}</div>;
}

export function ProjectList({ projects }: { projects: WorkspaceProject[] }) {
  if (!projects.length) return <div className="empty-state"><p>아직 관리 중인 프로젝트가 없습니다.</p><a href="#/new">새 프로젝트 분석</a></div>;
  return <div className="workspace-project-list">{projects.map(project => <article className="workspace-project-row" key={project.projectId}>
    <div className="section-heading"><div><h3><a href={projectLink(project.projectId)}>{project.name}</a></h3>
      <span>{project.sourceType === 'GITHUB' ? 'GitHub' : 'ZIP'}{project.githubRepositoryId != null ? ` · ${project.privateRepository ? '비공개' : '공개'} · 읽기 전용` : ''}</span></div><strong>{reviewStatus(project.latestReview)}</strong></div>
    <PriorityCounts assessment={project.latestReview?.riskSummary} />
    <p>최근 분석: {dateLabel(project.latestReview?.createdAt)} · 총 분석: {project.reviewCount}회</p>
    <ProgressBrief progress={project.latestProgress} />
    <a href={projectLink(project.projectId)}>프로젝트 열기</a>
  </article>)}</div>;
}

export function WorkspaceSummary({ data, name }: { data: WorkspaceResponse; name: string }) {
  return <>
    <header className="section-heading"><h2>{name}님의 프로젝트</h2><a className="primary-button" href="#/new">+ 새 프로젝트 분석</a></header>
    <dl className="workspace-counts dashboard-counts">
      <div><dt>관리 중인 프로젝트</dt><dd>{data.projectCount}</dd></div>
      <div><dt>배포 전 수정 필요</dt><dd>{data.blockedProjectCount}</dd></div>
      <div><dt>직접 확인 필요</dt><dd>{data.reviewRequiredProjectCount}</dd></div>
      <div><dt>분석 이력 있는 프로젝트</dt><dd>{data.analyzedProjectCount}</dd></div>
    </dl>
    {data.unassessedProjectCount > 0 && <p>미분석 또는 위험 평가가 없는 프로젝트 {data.unassessedProjectCount}개는 배포 가능으로 판단하지 않습니다.</p>}
    <section><h2>최근 분석된 프로젝트</h2><ProjectList projects={data.projects.slice(0, 5)} /></section>
    <p>목록의 상태와 집계는 저장된 위험 정책 기준입니다. 구조 검토 후보와 검사하지 못한 범위는 프로젝트의 분석 결과에서 별도로 확인하세요.</p>
    <section className="workspace-section"><h2>최근 보안 상태 변화</h2>
      {data.projects.filter(p => p.latestProgress?.baselineReviewId != null).slice(0, 5).map(project => <article key={project.projectId}>
        <h3><a href={projectLink(project.projectId, 'findings', project.latestReview?.reviewId, 'PROGRESS')}>{project.name}</a></h3>
        <ProgressBrief progress={project.latestProgress} />
      </article>)}
      {!data.projects.some(p => p.latestProgress?.baselineReviewId != null) && <p>재검사 후 이전 결과와의 변화가 여기에 표시됩니다.</p>}
    </section>
  </>;
}
