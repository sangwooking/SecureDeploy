import { useEffect, useRef, useState, type FormEvent } from 'react';
import { reviewGithubRepository, uploadZipForReview } from '../api/securityReviewApi';
import type { SecurityReviewResponse } from '../types/securityReview';
import type { UploadPolicy } from '../types/uploadPolicy';
import { validateZipUpload } from './zipUploadValidation';
import { ZipUploadGuidance } from './ZipUploadGuidance';

export function NewProjectAnalysis({ policy, policyError, retryPolicy, onComplete }: {
  policy: UploadPolicy | null; policyError: string; retryPolicy: () => void; onComplete: (result: SecurityReviewResponse) => void;
}) {
  const [mode, setMode] = useState<'ZIP' | 'GITHUB'>('ZIP');
  const [file, setFile] = useState<File | null>(null);
  const [url, setUrl] = useState('');
  const [enhanced, setEnhanced] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const active = useRef(true);
  useEffect(() => { active.current = true; return () => { active.current = false; }; }, []);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    let message = mode === 'ZIP' ? validateZipUpload(file, policy) : '';
    if (mode === 'GITHUB') {
      try { const parsed = new URL(url.trim()); if (parsed.protocol !== 'https:' || parsed.hostname !== 'github.com') message = 'https://github.com 저장소 URL을 입력해 주세요.'; }
      catch { message = '올바른 GitHub Repository URL을 입력해 주세요.'; }
    }
    if (message) { setError(message); return; }
    setBusy(true); setError('');
    try {
      const scanMode = enhanced ? 'AI_ENHANCED' : 'STANDARD';
      const result = mode === 'ZIP' ? await uploadZipForReview(file as File, scanMode) : await reviewGithubRepository(url.trim(), scanMode);
      if (active.current) onComplete(result);
    } catch (e) { if (active.current) setError(e instanceof Error ? e.message : '분석하지 못했습니다.'); }
    finally { if (active.current) setBusy(false); }
  };
  return <section className="workspace-section analysis-entry"><h2>새 프로젝트 분석</h2>
    <p>내 계정의 ZIP 프로젝트 이름 또는 GitHub 저장소 URL이 같으면 기존 프로젝트에 새 분석으로 연결됩니다. 다른 사용자의 프로젝트와 합치지 않습니다.</p>
    <form className="upload-panel review-panel" onSubmit={submit}>
      <fieldset disabled={busy}>
        <div className="mode-switch" aria-label="분석 방식 선택">
          <button type="button" className={`mode-button ${mode === 'ZIP' ? 'mode-button-active' : ''}`} onClick={() => { setMode('ZIP'); setError(''); }}>ZIP 업로드</button>
          <button type="button" className={`mode-button ${mode === 'GITHUB' ? 'mode-button-active' : ''}`} onClick={() => { setMode('GITHUB'); setError(''); }}>GitHub URL 입력</button>
        </div>
        {mode === 'ZIP' ? <label className="file-drop">ZIP 파일 선택<input type="file" accept=".zip,application/zip" onChange={event => {
          const selected = event.target.files?.[0] ?? null; setFile(selected); setError(selected ? validateZipUpload(selected, policy) : '');
        }} />{file?.name}</label> : <label className="github-input-wrap">Repository URL<input type="url" value={url} onChange={event => { setUrl(event.target.value); setError(''); }} required /></label>}
        <label className="semantic-opt-in"><input type="checkbox" checked={enhanced} onChange={event => setEnhanced(event.target.checked)} />AI 강화 분석</label>
        {enhanced && <p>선별·마스킹된 코드 일부가 외부 AI에 전달될 수 있으며 API 비용이 발생할 수 있습니다.</p>}
        {mode === 'ZIP' && <ZipUploadGuidance policy={policy} error={policyError} onRetry={retryPolicy} />}
        <button className="primary-button" type="submit" disabled={busy || (mode === 'ZIP' && !policy)}>{busy ? '분석 중...' : '분석 시작'}</button>
      </fieldset>
      {busy && <p role="status">프로젝트를 분석하고 저장하고 있습니다. 완료될 때까지 기다려 주세요.</p>}
      {error && <p role="alert" className="error-message">{error}</p>}
    </form>
  </section>;
}
