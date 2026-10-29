# AI-01 기존 AI 수정 기능 감사 및 제한적 통합 강화

시작 SHA: e0f9ca498c142f1130840a3a9e2cdefade9c8c06. 격리 브랜치 codex/ai01, worktree /private/tmp/securedeploy-ai01. 최종 SHA는 이 보고서를 포함한 커밋으로 git log에서 확인한다. 원격 push 및 실사용 배포는 수행하지 않는다.

## 기존 구현 감사

아래 경로는 저장소 기준이다. 실제 모델 성공 증거는 이번 작업에서 생성하지 않았다. transport 테스트는 실제 원격 모델 품질 검증이 아니다.

| 기능 | 구현·호출 관계 | UI 및 검증 상태 |
|---|---|---|
| Finding 수정 가이드 | ai/remediation/FindingRemediationService → RemediationContextFactory/RemediationSanitizer → Provider → RemediationOutputValidator → RemediationSnapshot | 제품 구현. STANDARD는 Template만 호출. FindingRemediationTest, RemediationGroundingTest, RemediationReviewIntegrationTest. 실제 모델 smoke는 키 없으면 skip |
| Semantic Review | ai/semantic/SemanticReviewService → SecuritySliceCollector/PromptBuilder → Provider → SemanticOutputValidator → SemanticSnapshot | SemanticReviewSection.tsx 연결. STANDARD에서는 NOT_REQUESTED. Template는 의미분석 미지원. SemanticReviewTest/IntegrationTest 및 OpenAiSemanticTransportTest는 통제 검증 |
| 실제 OpenAI | ai/service/RealOpenAiProvider.generateWorkspacePatch → 구조화 JSON schema → WorkspacePatch.parse | 제품 구현, 설정·키·Provider 가용성 필요. OpenAiPatchTransportTest는 통제 transport. 실제 모델 호출 미수행 |
| Template/Mock | TemplateAiProvider는 수정 설명 지원, WorkspacePatch는 AiProvider 기본 메서드에서 UnsupportedOperationException | Template 코드 Patch 생성은 미지원. EditingBrowserServer의 테스트 전용 Mockito Provider만 통제 수정안을 생성. 운영 Mock Provider 추가하지 않음 |
| 수정 제안 | editing/WorkspacePatchService.prepare/generate → EditingWorkspaceService.preparePatch/beginPatch/finishPatch | AiPatchPanel.tsx → api/editingApi.ts 연결. 명시 전송 동의, Provider 확인, timeout·quota·취소 지원 |
| 수정 검증 | WorkspacePatch.validate, ResponsePatchValidator → analyzers/typescript/response-patch.mjs | 파일 ID·행·hash 및 AST 계약 검증. 모델 경로를 파일 경로로 사용하지 않음. WorkspacePatchTest/ApiTest/ResponsePatchTest |
| Workspace 및 승인 | EditingWorkspaceController/Service, SourceArchive → applyPatch | 소유권·revision·파일 hash·경로·원본 commit 검증. 승인 전 원본 불변, 응답 계약 별도 동의, AI/수동 변경 출처 구분 |
| Diff·Patch·ZIP | 기존 Workspace 생성·다운로드 API 및 PatchDiff | 기존 제품 연결 유지. WorkspacePatchTest, EditingWorkspaceIntegrationTest 및 React browser 통제 흐름 |
| 재검사 | WorkspaceScanController → WorkspaceScanService → SecurityReviewFacade → WorkspaceScanPersistence | 기존 STANDARD 재검사 사용. 수정본 manifest·hash·원본 Review provenance 저장. 성공 상태는 검사 완료이며 SAFE·수정 성공 선언이 아님 |

Java 코드 위치의 공통 접두사는 src/main/java/com/securedeploy/, 테스트는 src/test/java/com/securedeploy/이다.

## 지원 구조 및 재사용

새 Rule Engine 및 분석 로직은 만들거나 변경하지 않았다. 기존 Worker v51과 모든 Rule을 그대로 재사용한다.

현재 제한적 코드 Patch 지원은 EXACT_GIT_COMMIT 원본의 .ts 파일, 최상위 Deno.serve의 직접 handler, return Response.json의 직접 객체, Source/Sink 근거가 일치하는 직접 Deno.env.get 속성이다. 다른 정상 속성은 허용된 단순 literal이어야 하며 원문과 순서를 그대로 보존하고 최소 한 속성을 유지한다. helper·별칭·중첩·전체 환경값 응답·변경된 원본·ZIP 미검증 원본은 거부한다. .properties의 기존 제한적 설정 Patch도 유지한다.

Express Lab 및 Express 응답 구조는 검토했으나 기존 validator가 Express receiver·handler 계약을 지원하지 않는다. 이번 작업에서는 지원을 확대하거나 실습앱·파일명·apiSecret 이름을 하드코딩하지 않았다. Express AI Patch는 미지원이다.

예시 통제 Diff(실제 운영 비밀값 없음):
```diff
-return Response.json({status: 'ok', diagnostic: Deno.env.get('API_SECRET')}, {status: 201});
+return Response.json({status: 'ok'}, {status: 201});
```
여기서 환경변수 이름은 합성 fixture의 식별자이며 비밀값을 읽거나 전송하지 않는다. 실제 모델 생성 결과가 아니다. 수정 대상 file ID·원본 행·hash·전후 코드·설명·검증 단계·제약은 기존 proposal View에 포함된다. API 필드 제거 영향은 서버 고정 안내와 별도 승인으로 표시한다.

## 이번 보완

1. Provider가 불확실성 목록을 빈 배열로 반환하면 INVALID로 거부한다.
2. Provider의 verificationSteps가 서버가 요구한 API 호환성·STANDARD 재검사 확인을 대체하지 못하게 합친다. 서버 제약 목록 보존은 기존 구현을 재사용한다.
3. 거부 시 파일 불변과 정상 제안에서 필수 확인 보존을 회귀 테스트로 검증한다.
4. 격리 browser fixture 서버에 포트 선택 및 8080 거부를 추가하고 browser script에 EDITING_API_URL을 추가한다.

## 해석 제한

Mock 생성·승인·재검사는 제품 연결 검증이며 실제 AI 능력 검증이 아니다. 모델 호출 승인·비용 승인을 받지 않았으므로 유료 모델은 호출하지 않는다. 이번 변경은 자동 SAFE 판정·동일 HTTP 진입점 증명·업무 기능 보존 판정기를 추가하지 않는다. Finding 부재만으로 수정 성공을 표시하지 않는다. 재검사 결과와 Coverage·후보 변화는 사용자가 검토해야 한다. 자동 구조 비교는 기존 NOT_COMPARED이다.

실사용 DB 내용을 조회하거나 hash를 새로 계산하지 않았으므로 데이터 보존의 전후 DB 대조는 미수행이다. 실사용 서버 재시작·배포·원본 데이터 작업은 하지 않는다. 기존 실앱 회귀 입력 7개는 INPUT_UNAVAILABLE 상태를 유지하며 새로 검증된 것으로 계산하지 않는다. 과거 실제 모델 smoke 성공 여부는 확인되지 않았다.

## React 제품 검증 및 증거

격리 H2, 테스트 전용 Mock Provider, Mock GitHub 원본, 실제 React, 실제 STANDARD 엔진을 사용했다. API 8087, React 5187. 제품 CORS 변경 없이 browser test proxy에서만 origin을 매핑했다. 유료 호출 0건.

1440·1024·768·390·320 px × 고정 키/요청 선택 키 2개 구조 = 총 10개 시나리오 통과. 제안 생성·거절·재생성·승인·재검사·ZIP/Patch 다운로드를 검증했다. 모든 파일의 ZIP hash 및 git apply 후 Patch hash와 workspace manifest/inputHash가 일치했다. 원본 Review 응답은 변경 전후 동일했다. 수동 변경 origin과 AI_APPROVED를 구분하는 기존 이력을 유지했다.

재검사 결과: 관련 흐름 후보 1→0, Risk REVIEW_REQUIRED 유지, Coverage PARTIAL 유지, score 93 유지, 일반 Finding 목록 유지, 파싱 파일 수 유지, 구조 비교 NOT_COMPARED, RESOLVED 0, NEW 0. 동일 HTTP handler를 자동 입증한 것은 아니며 운영 기능·API 소비자 호환성은 미검증이다.

증거 디렉터리: /private/tmp/securedeploy-ai01-evidence
- react-results.json: 모든 시나리오 및 해시 대조 결과
- MOCK-proposal-1440.png / MOCK-proposal-390.png: Diff·API 영향 안내·사용자 승인
- MOCK-comparison-1440.png / MOCK-comparison-390.png: 재검사 및 미해결 상태

전시 설명은 반드시 “Mock Provider로 제품 흐름 검증, 실제 모델 품질 미검증”으로 표기한다. 실제 AI 수정 성공 증거로 사용하지 않는다.

## 잔여 과제

실제 모델 호출 및 품질 검증, Express 응답 Patch 지원, 동일 HTTP 진입점·관련 함수·정상 기능의 수정 전후 자동 동등성 검증, ZIP 원본 기반 AI Patch는 이번에 완료되지 않았다. 최신 통합 흐름은 기존 Deno 지원 범위를 재사용한 것이며 새로 만든 AI 기능으로 주장하지 않는다. 실제 모델 승인 없이는 비용·외부 코드 전송을 진행하지 않는다.

## 보존·검증 방법

Node permission worker는 분석기 디렉터리 밖의 심볼릭 링크 의존성을 읽지 못하므로 TypeScript node_modules를 격리 worktree 내부에 복사했다. 최초 환경 실패 결과를 성공으로 계산하지 않는다. 이후 전체 재실행에서 새 테스트의 Mockito 재설정 오류 1건을 찾아 doAnswer로 수정한 뒤 최종 재실행했다.

실사용 프로세스 PID 10106(8080), 67918(5173)은 그대로 유지했다. 배포 JAR 및 analyzer.mjs SHA-256은 기존 artifact.json과 일치했다. 기본 main 1507041 및 미추적 평가 문서 3개가 그대로임을 재확인했다. 테스트 전용 서버는 검증 후 종료했다. DB 보존에 대한 직접 전후 내용 대조와 백업 복원 시험은 미수행이다.

## 최종 테스트 결과

- Backend: {'tests': 781, 'failures': 0, 'errors': 0, 'skipped': 9}; BUILD SUCCESSFUL.
- Worker: 1,329 통과.
- Frontend: 199 통과 및 tsc/Vite build 성공.
- Python Worker: 117 통과.
- 실제 React: Mock Provider 10개 시나리오 통과.
- git diff --check 통과.
- 세부 로그 및 backend-results.json: /private/tmp/securedeploy-ai01-evidence.
- 백엔드 skip 목록: com.securedeploy.ai.remediation.OpenAiRemediationLiveSmokeTest.generatesAdviceFromSyntheticFindingWithoutChangingRisk(), com.securedeploy.analysis.javaflow.JavaDataAccessTest.freshOfficialSpringGuideIsParsingNotAClaimOfRequestFlowSupport(), com.securedeploy.sca.FreezeOsvSmokeTest.livePublicPackagesRoundTripAndReplayWithoutAdditionalNetworkCalls(), com.securedeploy.analysis.javaflow.JavaSqlCorpusTest.recordFrozenPublicTruthWithoutChangingTheEngineToPass(), com.securedeploy.github.service.GitHubSourceSmokeTest.anonymousSmallPublicRepositoryReadOnly(), com.securedeploy.threatintel.ThreatIntelSmokeTest.officialSourcesReturnLog4ShellEvidence(), com.securedeploy.sca.PythonOsvSmokeTest.exactPublicPyPiVersionUsesExistingOsvClientWithBoundedRequests(), com.securedeploy.evaluation.WorkspaceEngineRegressionTest.retainedFreezeAssetsKeepRuleAndStructuralSignalsThroughWorkspacePipeline(), com.securedeploy.sca.OsvSmokeTest.knownLog4jAdvisoryIsReturnedByLiveOsv().

기존 WorkspacePatch/WorkspaceScan API 및 통합 테스트를 포함한 전체 실행에서 소유권·잘못된 hash·원본 범위·승인·수동 수정·Review/Snapshot 호환성 검증을 재사용했다. 실사용 DB replay나 실모델 증거로 계산하지 않는다.
