import { useEffect, useState } from 'react';
import type { AuthResponse } from '../types/securityReview';
import type { WorkspaceResponse } from '../types/workspace';
import type { UploadPolicy } from '../types/uploadPolicy';
import { fetchUploadPolicy, fetchWorkspace } from '../api/securityReviewApi';
import { parseWorkspaceRoute, projectLink } from './workspaceRoute';
import { ProjectList, WorkspaceSummary } from './WorkspaceSummary';
import { NewProjectAnalysis } from './NewProjectAnalysis';
import { ProjectWorkspace } from './ProjectWorkspace';
import { GitHubConnectionPanel } from './GitHubConnectionPanel';

export function Workspace({ session, onLogout }: { session: AuthResponse; onLogout: () => void }) {
  const [route, setRoute] = useState(() => parseWorkspaceRoute(window.location.hash));
  const [data, setData] = useState<WorkspaceResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [revision, setRevision] = useState(0);
  const [policy, setPolicy] = useState<UploadPolicy | null>(null);
  const [policyError, setPolicyError] = useState('');
  const [policyRetry, setPolicyRetry] = useState(0);
  useEffect(() => {
    const change = () => { setRoute(parseWorkspaceRoute(window.location.hash)); window.scrollTo(0, 0); };
    window.addEventListener('hashchange', change);
    return () => window.removeEventListener('hashchange', change);
  }, []);
  useEffect(() => {
    let active = true;
    setPolicy(null); setPolicyError('');
    void fetchUploadPolicy().then(value => { if (active) setPolicy(value); })
      .catch(e => { if (active) setPolicyError(e instanceof Error ? e.message : '업로드 정책을 불러오지 못했습니다.'); });
    return () => { active = false; };
  }, [policyRetry]);
  useEffect(() => {
    let active = true;
    setData(null); setError('');
    if (route.page !== 'dashboard' && route.page !== 'projects') { setLoading(false); return; }
    setLoading(true);
    void fetchWorkspace().then(value => { if (active) setData(value); })
      .catch(e => { if (active) setError(e instanceof Error ? e.message : '내 프로젝트를 불러오지 못했습니다.'); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [route.page, revision]);
  const currentPage = route.page === 'project' ? 'projects' : route.page;
  return <main className="app-shell"><section className="workspace">
    <header className="masthead"><div><p className="eyebrow">프로젝트 보안 관리</p><h1>SecureDeploy</h1></div>
      <div className="session-box"><span>{session.user.name}</span><button className="secondary-button" onClick={onLogout}>로그아웃</button></div></header>
    <nav className="workspace-navigation" aria-label="앱 메뉴">{[
      ['dashboard', '대시보드'], ['projects', '내 프로젝트'], ['new', '새 프로젝트'], ['account', '계정'],
    ].map(([id, label]) => <a key={id} href={`#/${id}`} aria-current={currentPage === id ? 'page' : undefined}>{label}</a>)}</nav>
    <div className="workspace-content">
      {(route.page === 'dashboard' || route.page === 'projects') && <>
        {loading && <p role="status">내 프로젝트를 불러오고 있습니다.</p>}
        {error && <div><p role="alert" className="error-message">{error}</p><button onClick={() => setRevision(value => value + 1)}>다시 불러오기</button></div>}
        {data && (route.page === 'dashboard' ? <WorkspaceSummary data={data} name={session.user.name} /> : <>
          <header className="section-heading"><h2>내 프로젝트 ({data.projectCount})</h2><a href="#/new">+ 새 프로젝트 분석</a></header><ProjectList projects={data.projects} />
        </>)}
      </>}
      {route.page === 'new' && <NewProjectAnalysis policy={policy} policyError={policyError} retryPolicy={() => setPolicyRetry(value => value + 1)}
        onComplete={result => { window.location.hash = result.projectId ? projectLink(result.projectId) : '#/projects'; }} />}
      {route.page === 'project' && <ProjectWorkspace key={route.projectId} route={route} policy={policy} policyError={policyError}
        retryPolicy={() => setPolicyRetry(value => value + 1)} onDeleted={() => { window.location.hash = '#/projects'; setRevision(value => value + 1); }} />}
      {route.page === 'account' && <section className="workspace-section"><h2>계정</h2>
        <dl className="technical-grid"><div><dt>이름</dt><dd>{session.user.name}</dd></div><div><dt>이메일</dt><dd>{session.user.email}</dd></div></dl>
        <GitHubConnectionPanel />
      </section>}
      {route.page === 'not-found' && <section><h2>페이지를 찾을 수 없습니다.</h2><a href="#/dashboard">대시보드로 돌아가기</a></section>}
    </div>
  </section></main>;
}
