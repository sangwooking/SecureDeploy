module.exports = () => {
  const source = { filePath: 'functions/api/items.ts', line: 3, functionName: 'onRequestGet', kind: 'QUERY_PARAMETER' };
  const sink = { ...source, line: 6, kind: 'D1_PREPARE' };
  const snapshot = { schemaVersion: 1, analyzerVersion: 'ts-server-v2', parserVersion: '6.0.3', status: 'PARTIAL',
    files: [{ filePath: source.filePath, parseStatus: 'PARSED', flowStatus: 'PARTIAL', entrypoints: 1, functionsAnalyzed: 1, limitations: ['CALL_TARGET_UNRESOLVED'] }],
    findings: [{ ruleId: 'TS_SQL_INPUT_FLOW', kind: 'SQL_INPUT_TO_QUERY', confidence: 'HIGH', disposition: 'REVIEW_REQUIRED',
      source, sink, flow: [source, { ...source, line: 4, kind: 'VARIABLE' }], defenses: [],
      limitations: ['QUERY_CONSTRUCTION_NOT_EXPLOIT_PROOF'], message: '요청에서 온 값이 쿼리 문자열에 전달됩니다.', recommendation: '정적인 SQL과 값 바인딩으로 분리한 뒤 재검사하세요.' }],
    sqlUses: [{ kind: 'INPUT_IN_QUERY', location: sink, trace: [source], defenses: [], limitations: [], executionObserved: true }],
    authorizationContexts: [{ entry: { ...source, line: 1, kind: 'PAGES_FUNCTION' }, checks: [], defenses: [], resources: [sink], conclusion: 'NOT_VERIFIED', limitations: [] }],
    limitations: ['전체 코드의 안전 여부는 확인하지 못했습니다.'] };
  snapshot.validatedFindings = [{ findingId: 'ts-flow:synthetic-only', sourceType: 'TYPESCRIPT_DATA_FLOW', analyzerVersion: 'ts-server-v2',
    ruleId:'TS_SQL_INPUT_FLOW', priority:'REVIEW_REQUIRED', comparisonPolicy:'NOT_COMPARED', location:sink,
    evidence:snapshot.findings, executionLocations:[{...sink,line:7,kind:'SQL_EXECUTION_CALL'}], title:'요청 값이 SQL 문자열과 실행 호출까지 전달됩니다',
    riskExplanation:'쿼리 문법으로 해석될 수 있습니다. 실제 공격 성공은 검증하지 않았습니다.', recommendedAction:'SQL을 고정하고 prepare(...).bind(...)로 값을 분리하세요.',
    verificationSteps:['표시된 경로와 입력 검사를 확인하세요.','정상 값과 따옴표가 포함된 테스트 입력으로 바인딩을 검증하세요.','같은 프로젝트를 재검사하세요. 해결 건수에는 자동 합산하지 않습니다.'] }];
  return snapshot;
};
