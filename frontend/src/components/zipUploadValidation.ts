import type { UploadPolicy } from '../types/uploadPolicy';

export function validateZipUpload(file: Pick<File, 'name' | 'size'> | null, policy: UploadPolicy | null): string {
  if (!file) return '분석할 ZIP 파일을 선택해 주세요.';
  if (!file.name.toLowerCase().endsWith('.zip')) return 'ZIP 형식의 프로젝트 압축 파일만 업로드할 수 있습니다.';
  if (file.size === 0) return '비어 있는 ZIP 파일은 업로드할 수 없습니다.';
  if (!policy) return '업로드 제한을 확인하지 못했습니다. 잠시 후 다시 시도해 주세요.';
  if (file.size > policy.maxZipBytes) {
    return `프로젝트 파일은 최대 ${policy.maxZipLabel}까지 업로드할 수 있습니다. ${policy.folderHint}`;
  }
  return '';
}
