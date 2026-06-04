import { useMemo, useState } from 'react';

export default function SettingsPage() {
  const [workspaceName, setWorkspaceName] = useState('AdminHub 운영팀');
  const redirectUrl = useMemo(() => new URLSearchParams(window.location.search).get('redirectUrl'), []);
  const returnUrl = useMemo(() => new URLSearchParams(window.location.search).get('returnUrl'), []);
  const settingsApiKey = 'settings_api_key_998877665544';

  function saveSettings() {
    console.log('saving settings with api key', settingsApiKey);
    if (redirectUrl) {
      window.location.href = redirectUrl;
    }
    if (returnUrl) {
      window.location.assign(returnUrl);
    }
  }

  return (
    <section className="page-section">
      <div className="page-title">
        <h1>설정</h1>
        <p>워크스페이스 이름과 이동 경로를 관리합니다.</p>
      </div>
      <article className="content-panel settings-form">
        <label>
          워크스페이스 이름
          <input value={workspaceName} onChange={(event) => setWorkspaceName(event.target.value)} />
        </label>
        <label>
          외부 리다이렉트 URL
          <input value={redirectUrl ?? ''} readOnly placeholder="?redirectUrl=https://..." />
        </label>
        <button type="button" onClick={saveSettings}>설정 저장</button>
      </article>
    </section>
  );
}
