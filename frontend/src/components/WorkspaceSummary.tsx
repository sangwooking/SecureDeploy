import type { WorkspaceResponse, WorkspaceProject } from '../types/workspace';
import type { ReviewHistoryResponse, ProgressAssessment } from '../types/securityReview';
import { deploymentLabels } from './reviewPresentation';
import { projectLink } from './workspaceRoute';
import { ProjectManagement } from './ProjectManagement';

export function reviewStatus(review?: ReviewHistoryResponse | null): string {
  return !review ? '분석 결과 없음' : review.riskSummary ? deploymentLabels[review.riskSummary.deploymentAssessment] : '위험 평가 미저장';
}
export function dateLabel(date?: string | null) { return date ? new Date(date).toLocaleString('ko-KR') : '아직 분석하지 않음'; }

export function PriorityCounts({ assessment, compact = false }: { assessment?: ProgressAssessment | null; compact?: boolean }) {
  return <dl className={`workspace-counts${compact ? ' compact-priority-counts' : ''}`}>
    <div><dt>반드시 처리</dt><dd>{assessment?.prioritySummary?.BLOCKING ?? '미평가'}</dd></div>
    <div><dt>{compact ? '배포 전 확인' : '배포 전 직접 확인'}</dt><dd>{assessment?.prioritySummary?.REVIEW_REQUIRED ?? '미평가'}</dd></div>
    <div><dt>수정 권장</dt><dd>{assessment?.prioritySummary?.SHOULD_FIX ?? '미평가'}</dd></div>
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

export function ProjectList({ projects, onDeleted }: { projects: WorkspaceProject[]; onDeleted?: () => void }) {
  if (!projects.length) return <div className="empty-state"><p>아직 관리 중인 프로젝트가 없습니다.</p><a href="#/new">새 프로젝트 분석</a></div>;
  return <div className="workspace-project-list">{projects.map(project => <article className="workspace-project-row" key={project.projectId}>
    <div className="project-row-identity"><h3><a href={projectLink(project.projectId)} title={project.name}>{project.name}</a></h3>
      <span className="project-row-status">{reviewStatus(project.latestReview)}</span></div>
    <PriorityCounts assessment={project.latestReview?.riskSummary} compact />
    <ProjectManagement project={project} onDeleted={onDeleted} />
  </article>)}</div>;
}

export function RecentProjects({ projects }: { projects: WorkspaceProject[] }) {
  if (!projects.length) return <ProjectList projects={projects} />;
  return <div className="recent-projects">{projects.map(project => <article className="workspace-project-row recent-project-row" key={project.projectId}>
    <div className="recent-project-identity"><h3><a href={projectLink(project.projectId)}>{project.name}</a></h3>
      <p>{dateLabel(project.latestReview?.createdAt)}</p></div>
    <span className={`policy-label policy-${project.latestReview?.riskSummary?.deploymentAssessment.toLowerCase() ?? 'unknown'}`}>{reviewStatus(project.latestReview)}</span>
    <PriorityCounts assessment={project.latestReview?.riskSummary} compact />
    <p className="recent-project-scope">검사 범위 <a href={projectLink(project.projectId, 'findings')}>결과에서 확인</a></p>
  </article>)}</div>;
}

export function WorkspaceSummary({ data, name }: { data: WorkspaceResponse; name: string }) {
  return <>
    <header className="section-heading page-heading"><div><p className="eyebrow">프로젝트 보안 현황</p><h2>{name}님의 프로젝트</h2><p className="page-description">먼저 확인할 문제와 최근 검사 결과를 모았습니다.</p></div><a className="primary-button" href="#/new">새 프로젝트 등록</a></header>
    <dl className="workspace-counts dashboard-counts">
      <div><dt>관리 중인 프로젝트</dt><dd>{data.projectCount}</dd></div>
      <div><dt>배포 전 수정 필요</dt><dd>{data.blockedProjectCount}</dd></div>
      <div><dt>직접 확인 필요</dt><dd>{data.reviewRequiredProjectCount}</dd></div>
      <div><dt>분석 이력 있는 프로젝트</dt><dd>{data.analyzedProjectCount}</dd></div>
    </dl>
    {data.unassessedProjectCount > 0 && <p>미분석 또는 위험 평가가 없는 프로젝트 {data.unassessedProjectCount}개는 배포 가능으로 판단하지 않습니다.</p>}
    <section className="dashboard-projects"><header className="section-heading"><h2>최근 프로젝트</h2><a href="#/projects">전체 프로젝트 보기</a></header><RecentProjects projects={data.projects.slice(0, 5)} /></section>
    <p className="section-footnote">집계는 저장된 위험 정책 기준입니다. 검사하지 못한 범위와 별도 검토 후보는 각 결과에서 확인하세요.</p>
    <section className="workspace-section"><h2>최근 보안 상태 변화</h2>
      {data.projects.filter(p => p.latestProgress?.baselineReviewId != null).slice(0, 5).map(project => <article key={project.projectId}>
        <h3><a href={projectLink(project.projectId, 'findings', project.latestReview?.reviewId, 'PROGRESS')}>{project.name}</a></h3>
        <ProgressBrief progress={project.latestProgress} />
      </article>)}
      {!data.projects.some(p => p.latestProgress?.baselineReviewId != null) && <p>재검사 후 이전 결과와의 변화가 여기에 표시됩니다.</p>}
    </section>
  </>;
}
