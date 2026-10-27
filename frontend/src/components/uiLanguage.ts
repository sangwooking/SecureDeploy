// Display labels only. Persisted API states and security decisions stay unchanged.
export const inspectionLabels: Record<string, string> = {
  COMPLETE: '지원하는 검사 범위를 확인했어요', COMPLETED: '선택한 영역의 검토를 마쳤어요',
  PARTIAL: '일부 코드와 동작은 확인하지 못했어요', FAILED: '검사를 완료하지 못했어요',
  UNKNOWN: '판단할 정보가 부족해요', NOT_RECORDED: '저장된 검사 기록이 없어요',
  NOT_INCLUDED: '이번 검사에 포함되지 않았어요', NOT_APPLICABLE: '지원하는 검사 대상이 없어요',
  DISABLED: '이 검사는 실행하지 않았어요', NO_MANIFEST: '지원하는 라이브러리 목록 파일이 없어요',
  UNAVAILABLE: '정보를 확인하지 못했어요', NOT_REQUESTED: '추가 검토를 요청하지 않았어요',
  NO_SUPPORTED_CONTEXT: '지원하는 검토 대상을 찾지 못했어요', REJECTED: '응답의 근거를 확인하지 못했어요',
  TIMEOUT: '제한 시간 안에 마치지 못했어요', NOT_COMPARED: '이전 검사와 비교하지 못했어요',
  NO_BASELINE: '비교할 이전 검사가 없어요',
};
export const inspectionLabel = (value?: string | null) => inspectionLabels[value ?? 'NOT_RECORDED'] ?? '상세 검사 기록을 확인해 주세요';
export const securityTerms = {
  libraries: '외부 라이브러리 보안', score: '검사 규칙 기준 참고 점수',
  evidence: '문제라고 판단한 근거', snapshot: '검사 당시 기록',
  unknown: inspectionLabels.UNKNOWN, notCompared: inspectionLabels.NOT_COMPARED,
} as const;
export const severityLabels: Record<string, string> = { CRITICAL: '매우 높음', HIGH: '높음', MEDIUM: '중간', LOW: '낮음' };
