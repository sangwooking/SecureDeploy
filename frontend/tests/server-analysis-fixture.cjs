module.exports = () => {
  const source = { filePath: 'functions/api/items.ts', line: 3, functionName: 'onRequestGet', kind: 'QUERY_PARAMETER' };
  const sink = { ...source, line: 6, kind: 'D1_PREPARE' };
  return { schemaVersion: 1, analyzerVersion: 'ts-server-v1', parserVersion: '6.0.3', status: 'PARTIAL',
    files: [{ filePath: source.filePath, parseStatus: 'PARSED', flowStatus: 'PARTIAL', entrypoints: 1, functionsAnalyzed: 1, limitations: ['CALL_TARGET_UNRESOLVED'] }],
    findings: [{ ruleId: 'TS_SQL_INPUT_FLOW', kind: 'SQL_INPUT_TO_QUERY', confidence: 'HIGH', disposition: 'REVIEW_REQUIRED',
      source, sink, flow: [source, { ...source, line: 4, kind: 'VARIABLE' }], defenses: [],
      limitations: ['QUERY_CONSTRUCTION_NOT_EXPLOIT_PROOF'], message: '요청에서 온 값이 쿼리 문자열에 전달됩니다.', recommendation: '정적인 SQL과 값 바인딩으로 분리한 뒤 재검사하세요.' }],
    sqlUses: [{ kind: 'INPUT_IN_QUERY', location: sink, trace: [source], defenses: [], limitations: [], executionObserved: true }],
    authorizationContexts: [{ entry: { ...source, line: 1, kind: 'PAGES_FUNCTION' }, checks: [], defenses: [], resources: [sink], conclusion: 'NOT_VERIFIED', limitations: [] }],
    limitations: ['전체 코드의 안전 여부는 확인하지 못했습니다.'] };
};
