import type { UploadPolicy } from '../types/uploadPolicy';

export function ZipUploadGuidance({ policy, error, onRetry }: {
  policy: UploadPolicy | null; error?: string; onRetry?: () => void;
}) {
  return <div className="zip-upload-guidance" aria-live="polite">
    {policy ? <>
      <strong>ZIP 파일 최대 {policy.maxZipLabel}</strong>
      <p>{policy.folderHint}</p>
    </> : error ? <>
      <p role="alert">{error}</p>
      {onRetry && <button type="button" className="secondary-button" onClick={onRetry}>제한 정보 다시 확인</button>}
    </> : <p>업로드 제한 확인 중...</p>}
  </div>;
}
