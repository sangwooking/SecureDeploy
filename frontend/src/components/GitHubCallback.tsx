import { useEffect, useState } from 'react';
import { completeGitHubConnection } from '../api/githubConnectionApi';

// OAuth codes stay in memory only; remove them before rendering or making further requests.
const params = new URLSearchParams(window.location.search);
const callback = params.has('code') || params.has('error')
  ? { code: params.get('code'), state: params.get('state'), denied: params.has('error') } : null;
if (callback) window.history.replaceState(null, '', `${window.location.pathname}#/account`);
export const hasGitHubCallback = callback != null;
let completion: Promise<unknown> | undefined;

export function GitHubCallback({ loggedIn, onDone }: { loggedIn: boolean; onDone: () => void }) {
  const [message, setMessage] = useState('GitHub 연결을 확인하고 있습니다.');
  const [busy, setBusy] = useState(true);
  useEffect(() => {
    let active = true;
    if (!loggedIn || !callback?.code || !callback.state || callback.denied) {
      setMessage('GitHub 연결이 승인되지 않았거나 로그인 세션이 없습니다. 로그인 후 계정에서 다시 연결해 주세요.'); setBusy(false); return;
    }
    completion ??= completeGitHubConnection(callback.code, callback.state);
    void completion.then(() => { if (active) setMessage('GitHub 계정이 연결되었습니다. 분석할 저장소를 선택해 주세요.'); })
      .catch(e => { if (active) setMessage(e instanceof Error ? e.message : 'GitHub 연결에 실패했습니다.'); })
      .finally(() => { callback.code = null; callback.state = null; if (active) setBusy(false); });
    return () => { active = false; };
  }, [loggedIn]);
  return <main className="app-shell"><section className="workspace-section"><h1>GitHub 연결</h1>
    <p role="status">{message}</p><button disabled={busy} onClick={onDone}>계정으로 돌아가기</button>
  </section></main>;
}
