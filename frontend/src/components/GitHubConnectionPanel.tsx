import { useEffect, useState } from 'react';
import { beginGitHubConnection, disconnectGitHub, fetchGitHubConnection, fetchGitHubInstallations, fetchConnectedRepositories } from '../api/githubConnectionApi';
import type { ConnectedRepository, GitHubConnection, GitHubInstallation } from '../types/githubConnection';

export function GitHubConnectionPanel({ onSelect }: { onSelect?: (repository: ConnectedRepository | null) => void }) {
  const [connection, setConnection] = useState<GitHubConnection | null>(null);
  const [installations, setInstallations] = useState<GitHubInstallation[]>([]);
  const [installationPage, setInstallationPage] = useState(1);
  const [moreInstallations, setMoreInstallations] = useState(false);
  const [installation, setInstallation] = useState(0);
  const [repositories, setRepositories] = useState<ConnectedRepository[]>([]);
  const [page, setPage] = useState(1);
  const [more, setMore] = useState(false);
  const [selected, setSelected] = useState(0);
  const [revision, setRevision] = useState(0);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const picker = Boolean(onSelect);
  useEffect(() => {
    let active = true;
    setLoading(true); setError('');
    void fetchGitHubConnection().then(value => { if (active) setConnection(value); })
      .catch(e => { if (active) setError(e instanceof Error ? e.message : '연결 상태를 불러오지 못했습니다.'); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [revision]);
  useEffect(() => {
    if (!connection?.connected || !picker) return;
    let active = true; setLoading(true); setError('');
    void fetchGitHubInstallations(installationPage).then(value => {
      if (active) { setInstallations(previous => installationPage === 1 ? value.installations : [...previous, ...value.installations]); setMoreInstallations(value.hasNextPage); }
    }).catch(e => { if (active) setError(e instanceof Error ? e.message : 'App 설치를 확인하지 못했습니다.'); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [connection, installationPage, picker]);
  useEffect(() => {
    if (!installation || !connection?.connected) return;
    let active = true; setLoading(true); setError('');
    void fetchConnectedRepositories(installation, page).then(value => {
      if (active) { setRepositories(previous => page === 1 ? value.repositories : [...previous, ...value.repositories]); setMore(value.hasNextPage); }
    }).catch(e => { if (active) setError(e instanceof Error ? e.message : '저장소 접근 권한을 확인하지 못했습니다.'); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [installation, page, connection]);
  const connect = async () => {
    setBusy(true); setError('');
    try {
      const result = await beginGitHubConnection();
      const url = new URL(result.authorizationUrl);
      if (url.origin !== 'https://github.com' || url.pathname !== '/login/oauth/authorize' || url.username || url.password) throw new Error('GitHub 연결 주소가 올바르지 않습니다.');
      window.location.assign(url.href);
    } catch (e) { setError(e instanceof Error ? e.message : 'GitHub 연결을 시작하지 못했습니다.'); setBusy(false); }
  };
  const unlink = async () => {
    if (!window.confirm('GitHub 연결을 해제할까요? 기존 분석 이력은 유지되며 재검사에는 다시 연결해야 합니다.')) return;
    setBusy(true); setError(''); onSelect?.(null); setSelected(0); setInstallation(0); setRepositories([]); setInstallations([]);
    try { const result = await disconnectGitHub(); setNotice(result.message); setRevision(value => value + 1); }
    catch (e) { setError(e instanceof Error ? e.message : '연결을 해제하지 못했습니다.'); }
    finally { setBusy(false); }
  };
  return <section className="github-connection" aria-label="GitHub 계정 연결"><h3>GitHub 연결</h3>
    {loading && <p role="status">GitHub 접근 권한을 확인하고 있습니다.</p>}
    {connection && !connection.configured && <p>GitHub App 설정이 아직 준비되지 않았습니다. 공개 URL 또는 ZIP 분석을 이용해 주세요.</p>}
    {connection?.login && <p>연결 계정: <strong>{connection.login}</strong>{connection.reconnectRequired ? ' · 재연결 필요' : ''}</p>}
    {connection?.configured && <div className="result-actions">
      <button type="button" className="secondary-button" disabled={busy} onClick={() => void connect()}>{connection.connected ? '인증 갱신' : 'GitHub 연결'}</button>
      {connection.installationUrl && <a href={connection.installationUrl} target="_blank" rel="noopener noreferrer">App 설치 / 저장소 승인</a>}
      {connection.login && <button type="button" className="secondary-button" disabled={busy} onClick={() => void unlink()}>연결 해제</button>}
    </div>}
    {connection?.connected && picker && <>
      {!loading && installations.length === 0 && <p>읽기 전용 App 설치 또는 저장소 승인이 필요합니다.</p>}
      <label>App 설치 계정<select value={installation} disabled={busy || loading} onChange={event => {
        setInstallation(Number(event.target.value)); setRepositories([]); setSelected(0); setPage(1); setMore(false); onSelect?.(null);
      }}><option value={0}>설치 계정 선택</option>{installations.map(item => <option key={item.installationId} value={item.installationId}>{item.account}</option>)}</select></label>
      {moreInstallations && <button type="button" className="secondary-button" disabled={loading || installationPage >= 10} onClick={() => setInstallationPage(value => value + 1)}>설치 계정 더 보기</button>}
      {installation > 0 && <label>접근 가능한 저장소<select value={selected} disabled={busy || loading} onChange={event => {
        const id = Number(event.target.value); setSelected(id); onSelect?.(repositories.find(item => item.repositoryId === id) ?? null);
      }}><option value={0}>저장소 선택</option>{repositories.map(item => <option key={item.repositoryId} value={item.repositoryId}>{item.fullName} · {item.privateRepository ? '비공개' : '공개'}</option>)}</select></label>}
      {more && <button type="button" className="secondary-button" disabled={loading || page >= 10} onClick={() => setPage(value => value + 1)}>저장소 더 보기</button>}
      {selected > 0 && <p>읽기 권한 확인됨 · 기본 branch: {repositories.find(item => item.repositoryId === selected)?.defaultBranch}. 분석 시작 시 권한을 다시 확인합니다.</p>}
      {installation > 0 && !loading && !error && repositories.length === 0 && <p>선택할 수 있는 저장소가 없습니다. 사용자 권한과 App의 선택된 저장소 범위를 확인해 주세요.</p>}
    </>}
    <button type="button" className="secondary-button" disabled={busy || loading} onClick={() => { onSelect?.(null); setSelected(0); setInstallation(0); setPage(1); setInstallationPage(1); setRevision(value => value + 1); }}>연결 상태 새로고침</button>
    {error && <p role="alert" className="error-message">{error}</p>}{notice && <p role="status">{notice}</p>}
  </section>;
}
