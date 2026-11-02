import { useEffect, useRef, useState } from 'react';
import { deleteReview, fetchProjectDetail, fetchProjectReviews, fetchReviewDetail, reviewGithubRepository, uploadZipForReview } from '../api/securityReviewApi';
import type { ProjectDetail } from '../types/workspace';
import type { ReviewHistoryResponse, ScanMode, SecurityReviewResponse } from '../types/securityReview';
import type { UploadPolicy } from '../types/uploadPolicy';
import { PriorityCounts, dateLabel, reviewStatus } from './WorkspaceSummary';
import { projectLink, projectTabs, parseWorkspaceRoute, type WorkspaceRoute } from './workspaceRoute';
import { ProjectReviewResult } from './ProjectReviewResult';
import { RescanForm } from './RescanForm';
import { GitHubSourceInfo } from './GitHubSourceInfo';
import { ReviewProgressPanel } from './ReviewProgressPanel';
import { ProjectManagement } from './ProjectManagement';

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
  const lastResults=useRef<{projectId:number;href:string}|null>(null);
  if(route.tab==='findings')lastResults.current={projectId:route.projectId,href:projectLink(route.projectId,'findings',route.reviewId,route.view,route.selection)};
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
      window.location.hash = projectLink(route.projectId, 'history', result.reviewId ?? undefined, 'PROGRESS');
      setRevision(value => value + 1);
    } catch (e) { if (active.current) setError(e instanceof Error ? e.message : '재검사에 실패했습니다. 이전 결과는 유지됩니다.'); }
    finally { if (active.current) setBusy(false); }
  };
  if (loading) return <p role="status">프로젝트를 불러오고 있습니다.</p>;
  if (!data) return <section><p role="alert" className="error-message">{error}</p><a href="#/projects">내 프로젝트로 돌아가기</a>
    <button className="secondary-button" onClick={() => setRevision(value => value + 1)}>다시 불러오기</button></section>;
  const { project, history, review } = data;
  const latestSelected = review?.reviewId === project.latestReview?.reviewId;
  const previousSelection=parseWorkspaceRoute(lastResults.current?.href??'');
  const editingReviewId=review?.sourceType==='WORKSPACE'&&review.workspaceScan?.baselineVerified&&history.some(h=>h.reviewId===review.workspaceScan?.originalReviewId)?review.workspaceScan.originalReviewId:route.reviewId??review?.reviewId;
  const editSelection=route.selection??(previousSelection.page==='project'&&previousSelection.projectId===route.projectId&&previousSelection.reviewId===editingReviewId?previousSelection.selection:undefined);
  return <section className="project-workspace">
    <p className="result-breadcrumb"><a href="#/projects">내 프로젝트</a> / {project.name}</p>
    <header className="workspace-section project-heading"><p className="eyebrow">프로젝트</p><h2>{project.name}</h2>

      {project.githubRepositoryId != null && <p>{project.privateRepository ? '비공개' : '공개'} 저장소 · GitHub App 읽기 전용 · 최근 분석 시점 기준</p>}
      <div className="project-heading-meta"><strong className={`policy-label policy-${project.latestReview?.riskSummary?.deploymentAssessment.toLowerCase() ?? 'unknown'}`}>{reviewStatus(project.latestReview)}</strong><p>최근 분석: {dateLabel(project.latestReview?.createdAt)}</p></div>
    </header>
    <details className="project-more"><summary>프로젝트 정보·관리</summary><a href={projectLink(project.projectId,'settings')}>프로젝트 설정·삭제</a>{project.repositoryUrl&&<p>{project.repositoryUrl}</p>}</details>
    <nav className="project-navigation" aria-label="프로젝트 메뉴">{projectTabs.map(tab => <a key={tab.id} href={tab.id==='findings'&&lastResults.current?.projectId===project.projectId?lastResults.current.href:projectLink(project.projectId, tab.id,tab.id==='edit'?editingReviewId:undefined,undefined,tab.id==='edit'?editSelection:undefined)} aria-current={route.tab === tab.id ? 'page' : undefined}>{tab.label}</a>)}</nav>
    {notice && <p role="status" className="feedback-message feedback-success">{notice}</p>}
    {error && <p role="alert" className="error-message">{error}</p>}
    {busy && <p role="status">요청을 처리하고 있습니다. 잠시 기다려 주세요.</p>}
    {(route.tab === 'findings'||route.tab === 'edit') && <section className="workspace-section">
      {review ? <>
        {!latestSelected && <p className="review-caution">과거 분석 #{review.reviewId}의 저장된 결과입니다. 현재 상태가 아닙니다. <a href={projectLink(project.projectId, 'findings')}>최신 분석 보기</a></p>}
        <ProjectReviewResult key={`${review.reviewId}:${revision}`} result={review} view={route.view} selection={route.selection}
          editing={route.tab==='edit'} onEditingChange={(value,selection)=>{window.location.hash=projectLink(project.projectId,value?'edit':'findings',route.reviewId??review.reviewId,route.view,selection);}}
          onView={(view,selection) => { window.location.hash = projectLink(project.projectId, view==='PROGRESS'?'history':'findings', route.reviewId??review.reviewId??undefined, view,selection); }}
          onRescan={() => { window.location.hash = projectLink(project.projectId, 'rescan'); }} />
      </> : <><p>저장된 검사 결과가 없어 수정할 원본을 아직 확인할 수 없어요.</p><a className="primary-button" href={projectLink(project.projectId,'rescan')}>프로젝트 검사하기</a></>}
    </section>}
    {route.tab === 'history' && <section className="workspace-section history-panel"><h2>검사 기록 ({history.length})</h2>
      {!history.length && <p>저장된 분석 결과가 없습니다.</p>}
      {route.view==='PROGRESS'&&route.reviewId&&review?<><a href={projectLink(project.projectId,'history')}>검사 기록 목록으로 돌아가기</a><h3>검사 #{review.reviewId}의 변화</h3><p>{dateLabel(review.createdAt)}</p><ReviewProgressPanel result={review}/></>:<div className="history-list">{history.map(item => <article className="workspace-history-row" key={item.reviewId}>
        <h3>분석 #{item.reviewId} · {dateLabel(item.createdAt)}</h3><p>{item.sourceType === 'WORKSPACE' ? '작업 공간 수정본' : item.sourceType} · {reviewStatus(item)}</p>
        <p className="history-engine">{review?.reviewId===item.reviewId?`검사 엔진: ${review.serverAnalysis?.analyzerVersion??'미기록'} · 검사 범위: ${review.coverage?.status??'UNKNOWN'}`:'검사 엔진과 분석 범위는 저장된 결과에서 확인할 수 있어요.'}</p><div className="result-actions"><a className="history-item" href={projectLink(project.projectId, 'findings', item.reviewId, 'SUMMARY')}>결과 보기</a>
          {item.comparisonAvailable ? <a href={projectLink(project.projectId, 'history', item.reviewId, 'PROGRESS')}>변화 보기</a> : <span>이전 분석과 비교 근거 없음</span>}
</div><details className="history-item-details"><summary>검사 근거·관리</summary>        {item.sourceType === 'GITHUB' && <GitHubSourceInfo source={item.sourceMetadata} compact />}
        <PriorityCounts assessment={item.riskSummary} />
        <p>위험 평가 항목 {item.findingCount ?? '미평가'}건 · AI 추가 후보 {item.riskSummary?.semanticCandidateCount ?? '미평가'}건 (별도)</p>
          <button className="delete-button" disabled={busy} onClick={() => void removeReview(item)}>분석 삭제</button></details>
      </article>)}</div>}
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
      <p>프로젝트를 삭제하면 연결된 분석 결과와 저장된 수정 작업도 모두 삭제됩니다.</p>
      <ProjectManagement project={project} onDeleted={onDeleted} variant="settings" />
    </section>}
  </section>;
}
