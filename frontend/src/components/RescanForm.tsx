import { useState, type FormEvent } from 'react';
import type { ScanMode, SecurityReviewResponse } from '../types/securityReview';
import type { UploadPolicy } from '../types/uploadPolicy';
import { validateZipUpload } from './zipUploadValidation';
import { ZipUploadGuidance } from './ZipUploadGuidance';

export function RescanForm({ result, onScan, onCancel, uploadPolicy = null, policyError, onRetryPolicy }: {
  result: Pick<SecurityReviewResponse, 'projectId' | 'projectName' | 'sourceType' | 'repositoryUrl'>;
  onScan: (file: File | null, mode: ScanMode) => void; onCancel: () => void;
  uploadPolicy?: UploadPolicy | null; policyError?: string; onRetryPolicy?: () => void;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [mode, setMode] = useState<ScanMode>('STANDARD');
  const [error, setError] = useState('');
  if (result.sourceType === 'WORKSPACE') return <section><h3>수정본 검사 이력</h3><p>이 결과는 GitHub의 원본 commit이 아닌 작업 공간 수정본 검사입니다. 기존 작업 공간에서 다시 검사하거나 다운로드한 ZIP을 새로 분석해 주세요.</p><button type="button" onClick={onCancel}>결과로 돌아가기</button></section>;
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (result.sourceType === 'ZIP') {
      const message = validateZipUpload(file, uploadPolicy);
      if (message) { setError(message); return; }
    }
    onScan(file, mode);
  };
  return <form className="rescan-form" onSubmit={submit} aria-label="프로젝트 다시 검사">
    <h3>{result.projectName} 다시 검사</h3>
    <p>같은 프로젝트에 새 분석 이력으로 저장합니다. 비교 기준은 분석 저장 시점의 가장 최근 이력입니다.</p>
    {result.sourceType === 'ZIP' ? <label>수정된 프로젝트 ZIP을 다시 업로드하세요.
      <input type="file" accept=".zip" required onChange={event => {
        const selected = event.target.files?.[0] ?? null;
        setFile(selected); setError(selected ? validateZipUpload(selected, uploadPolicy) : '');
      }} />
    </label> : <p className="finding-location">최신 상태를 가져올 저장소: <strong>{result.repositoryUrl}</strong></p>}
    {result.sourceType === 'ZIP' && <ZipUploadGuidance policy={uploadPolicy} error={policyError} onRetry={onRetryPolicy} />}
    <label>분석 모드 <select value={mode} onChange={event => setMode(event.target.value as ScanMode)}>
      <option value="STANDARD">기본 분석</option><option value="AI_ENHANCED">AI 강화 분석</option>
    </select></label>
    {mode === 'AI_ENHANCED' && <p>선별·마스킹된 코드가 외부 AI에 전달될 수 있으며 API 비용이 발생할 수 있습니다.</p>}
    {result.sourceType === 'GITHUB' && <p>연결된 저장소는 사용자 권한과 App 승인 범위를 다시 확인합니다. 권한이 없으면 기존 이력을 유지하고 재검사를 중단합니다. <a href="#/account">GitHub 연결 관리</a></p>}
    <p>기본 분석에서도 패키지 이름·생태계·확정 버전은 OSV에, 공개 취약점 식별자는 EPSS/KEV 조회에 사용됩니다.</p>
    {error && <p role="alert" className="error-message">{error}</p>}
    <div className="result-actions"><button type="submit" disabled={result.sourceType === 'ZIP' && !uploadPolicy}>대상 확인 후 다시 검사</button>
      <button type="button" className="secondary-button" onClick={onCancel}>취소</button></div>
  </form>;
}
