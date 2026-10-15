import { useEffect, useRef, useState } from 'react';
import { deleteProject, deleteReview, fetchProjectDetail, fetchProjectReviews, fetchReviewDetail, reviewGithubRepository, uploadZipForReview } from '../api/securityReviewApi';
import type { ProjectDetail } from '../types/workspace';
import type { ReviewHistoryResponse, ScanMode, SecurityReviewResponse } from '../types/securityReview';
import type { UploadPolicy } from '../types/uploadPolicy';
import { PriorityCounts, ProgressBrief, dateLabel, reviewStatus } from './WorkspaceSummary';
import { allRiskFindings, findingTitle, priorityLabels } from './reviewPresentation';
import { projectLink, projectTabs, type WorkspaceRoute } from './workspaceRoute';
import { ProjectReviewResult } from './ProjectReviewResult';
import { RescanForm } from './RescanForm';
import { GitHubSourceInfo } from './GitHubSourceInfo';

export function ProjectWorkspace({ route, policy, policyError, retryPolicy, onDeleted }: {
  route: Extract<WorkspaceRoute, { page: 'project' }>; policy: UploadPolicy | null; policyError: string;
  retryPolicy: () => void; onDeleted: () => void;
}) {
  const [data, setData] = useState<{ project: ProjectDetail; history: ReviewHistoryResponse[]; review: SecurityReviewResponse | null } | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [revision, setRevision] = useState(0);
  const active = useRef(true);
  useEffect(() => { active.current = true; return () => { active.current = false; }; }, []);
  useEffect(() => {
    let cancelled = false;
    setData(null); setLoading(true); setError('');
    void (async () => {
      try {
        const project = await fetchProjectDetail(route.projectId);
        const history = await fetchProjectReviews(route.projectId);
        const id = route.reviewId ?? project.latestReview?.reviewId;
        if (id && !history.some(h => h.reviewId === id)) throw new Error('이 프로젝트에 속하지 않은 분석 결과입니다.');
        const review = id ? await fetchReviewDetail(id) : null;
        if (review && review.projectId !== project.projectId) throw new Error('프로젝트와 분석 결과가 일치하지 않습니다.');
        if (!cancelled) setData({ project, history, review });
      } catch (e) { if (!cancelled) setError(e instanceof Error ? e.message : '프로젝트를 불러오지 못했습니다.'); }
      finally { if (!cancelled) setLoading(false); }
    })();
    return () => { cancelled = true; };
  }, [route.projectId, route.reviewId, revision]);

  const removeProject = async () => {
    if (!data || !window.confirm(`“${data.project.name}” 프로젝트와 모든 분석 이력을 삭제할까요? 이 작업은 되돌릴 수 없습니다.`)) return;
    setBusy(true); setError('');
    try { await deleteProject(route.projectId); if (active.current) { setData(null); onDeleted(); } }
    catch (e) { if (active.current) setError(e instanceof Error ? e.message : '삭제하지 못했습니다.'); }
    finally { if (active.current) setBusy(false); }
  };
  const removeReview = async (review: ReviewHistoryResponse) => {
    if (!window.confirm(`분석 #${review.reviewId}을 삭제할까요? 프로젝트는 유지됩니다.`)) return;
    setBusy(true); setError('');
    try {
      await deleteReview(review.reviewId);
      if (active.current) { setNotice('분석 결과를 삭제했습니다. 남은 이력 기준으로 표시합니다.'); window.location.hash = projectLink(route.projectId, 'history'); setRevision(value => value + 1); }
    } catch (e) { if (active.current) setError(e instanceof Error ? e.message : '삭제하지 못했습니다.'); }
    finally { if (active.current) setBusy(false); }
  };
  const rescan = async (file: File | null, mode: ScanMode) => {
    if (!data) return;
    setBusy(true); setError(''); setNotice('');
    try {
      const result = data.project.sourceType === 'ZIP'
        ? await uploadZipForReview(file as File, mode, route.projectId)
        : await reviewGithubRepository(data.project.repositoryUrl ?? '', mode, route.projectId);
      if (!active.current) return;
      setNotice('재검사를 완료했습니다. 이전 분석과 현재 분석의 변화를 확인하세요.');
      window.location.hash = projectLink(route.projectId, 'findings', result.reviewId ?? undefined, 'PROGRESS');
      setRevision(value => value + 1);
    } catch (e) { if (active.current) setError(e instanceof Error ? e.message : '재검사에 실패했습니다. 이전 결과는 유지됩니다.'); }
    finally { if (active.current) setBusy(false); }
  };
  if (loading) return <p role="status">프로젝트를 불러오고 있습니다.</p>;
  if (!data) return <section><p role="alert" className="error-message">{error}</p><a href="#/projects">내 프로젝트로 돌아가기</a>
    <button className="secondary-button" onClick={() => setRevision(value => value + 1)}>다시 불러오기</button></section>;
  const { project, history, review } = data;
  const latestSelected = review?.reviewId === project.latestReview?.reviewId;
  const order = { BLOCKING: 0, REVIEW_REQUIRED: 1, SHOULD_FIX: 2, INFORMATIONAL: 3 };
  const first = review ? allRiskFindings(review).sort((a, b) => order[a.priority] - order[b.priority]).slice(0, 3) : [];
  return <section className="project-workspace">
    <p className="result-breadcrumb"><a href="#/projects">내 프로젝트</a> / {project.name}</p>
    <header className="workspace-section"><h2>{project.name}</h2>
      <p>{project.sourceType === 'GITHUB' ? 'GitHub' : 'ZIP'}{project.repositoryUrl && ` · ${project.repositoryUrl}`}</p>
      <strong>{reviewStatus(project.latestReview)}</strong><p>최근 분석: {dateLabel(project.latestReview?.createdAt)}</p>
    </header>
    <nav className="project-navigation" aria-label="프로젝트 메뉴">{projectTabs.map(tab => <a key={tab.id} href={projectLink(project.projectId, tab.id)} aria-current={route.tab === tab.id ? 'page' : undefined}>{tab.label}</a>)}</nav>
    {notice && <p role="status" className="feedback-message feedback-success">{notice}</p>}
    {error && <p role="alert" className="error-message">{error}</p>}
    {busy && <p role="status">요청을 처리하고 있습니다. 잠시 기다려 주세요.</p>}
    {route.tab === 'overview' && <section className="workspace-section">
      {project.sourceType === 'GITHUB' && project.latestReview && <GitHubSourceInfo source={project.latestReview.sourceMetadata} />}
      <h2>현재 보안 상태</h2><PriorityCounts assessment={project.latestReview?.riskSummary} />
      <h3>최근 변화</h3><ProgressBrief progress={latestSelected && review?.comparison ? review.comparison : null} />
      <h3>가장 먼저 처리할 문제</h3>
      {first.length && review ? <ol className="next-actions">{first.map(f => <li key={f.findingId}><a href={projectLink(project.projectId, 'findings', undefined, f.priority === 'INFORMATIONAL' ? 'SHOULD_FIX' : f.priority)}>{priorityLabels[f.priority]} · {findingTitle(review, f)}</a></li>)}</ol>
        : <p>{review ? '저장된 위험 평가 항목이 없습니다. 분석 완성도를 확인하세요.' : '아직 분석 결과가 없습니다.'}</p>}
      {project.latestReview?.riskSummary && <p>AI 추가 후보 {project.latestReview.riskSummary.semanticCandidateCount}건은 배포 판단과 별도로 직접 확인하세요.</p>}
      <div className="result-actions"><a href={projectLink(project.projectId, 'findings')}>발견된 문제 보기</a><a href={projectLink(project.projectId, 'rescan')}>{project.sourceType === 'GITHUB' ? 'GitHub 다시 검사' : '다시 검사하기'}</a></div>
    </section>}
    {route.tab === 'findings' && <section className="workspace-section">
      {review ? <>
        {!latestSelected && <p className="review-caution">과거 분석 #{review.reviewId}의 저장된 결과입니다. 현재 상태가 아닙니다. <a href={projectLink(project.projectId, 'findings')}>최신 분석 보기</a></p>}
        <ProjectReviewResult key={`${review.reviewId}:${revision}`} result={review} view={route.view}
          onView={view => { window.location.hash = projectLink(project.projectId, 'findings', route.reviewId, view); }}
          onRescan={() => { window.location.hash = projectLink(project.projectId, 'rescan'); }} />
      </> : <p>분석 결과가 없습니다. 재검사에서 프로젝트를 분석해 주세요.</p>}
    </section>}
    {route.tab === 'history' && <section className="workspace-section history-panel"><h2>분석 이력 ({history.length})</h2>
      {!history.length && <p>저장된 분석 결과가 없습니다.</p>}
      <div className="history-list">{history.map(item => <article className="workspace-history-row" key={item.reviewId}>
        <h3>분석 #{item.reviewId} · {dateLabel(item.createdAt)}</h3><p>{item.sourceType} · {reviewStatus(item)}</p>
        {item.sourceType === 'GITHUB' && <GitHubSourceInfo source={item.sourceMetadata} compact />}
        <PriorityCounts assessment={item.riskSummary} />
        <p>위험 평가 항목 {item.findingCount ?? '미평가'}건 · AI 추가 후보 {item.riskSummary?.semanticCandidateCount ?? '미평가'}건 (별도)</p>
        <div className="result-actions"><a className="history-item" href={projectLink(project.projectId, 'findings', item.reviewId, 'SUMMARY')}>결과 보기</a>
          {item.comparisonAvailable ? <a href={projectLink(project.projectId, 'findings', item.reviewId, 'PROGRESS')}>변화 보기</a> : <span>이전 분석과 비교 근거 없음</span>}
          <button className="delete-button" disabled={busy} onClick={() => void removeReview(item)}>분석 삭제</button></div>
      </article>)}</div>
    </section>}
    {route.tab === 'rescan' && <section className="workspace-section"><h2>재검사</h2>
      <p>{project.sourceType === 'ZIP' ? '수정한 프로젝트 ZIP을 다시 업로드해 주세요. 가장 최근 분석 결과와 자동으로 비교합니다.' : '등록된 GitHub 저장소를 다시 가져와 분석합니다.'}</p>
      <fieldset disabled={busy}><RescanForm result={{ projectId: project.projectId, projectName: project.name, sourceType: project.sourceType, repositoryUrl: project.repositoryUrl }}
        uploadPolicy={policy} policyError={policyError} onRetryPolicy={retryPolicy} onScan={(file, mode) => void rescan(file, mode)}
        onCancel={() => { window.location.hash = projectLink(project.projectId); }} /></fieldset>
    </section>}
    {route.tab === 'settings' && <section className="workspace-section"><h2>프로젝트 설정</h2>
      <dl className="technical-grid"><div><dt>프로젝트명</dt><dd>{project.name}</dd></div><div><dt>분석 방식</dt><dd>{project.sourceType}</dd></div>
        {project.repositoryUrl && <div><dt>GitHub URL</dt><dd>{project.repositoryUrl}</dd></div>}
        <div><dt>생성일</dt><dd>{dateLabel(project.createdAt)}</dd></div><div><dt>최근 분석</dt><dd>{dateLabel(project.latestReview?.createdAt)}</dd></div></dl>
      <p>프로젝트를 삭제하면 연결된 분석 결과도 모두 삭제됩니다.</p>
      <button className="delete-button" disabled={busy} onClick={() => void removeProject()}>프로젝트 삭제</button>
    </section>}
  </section>;
}
