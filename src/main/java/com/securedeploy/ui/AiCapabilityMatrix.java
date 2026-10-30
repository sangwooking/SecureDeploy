package com.securedeploy.ui;
import java.util.List;
/** Product support contracts. Patchability describes validation scope, never model quality or runtime safety. */
public final class AiCapabilityMatrix {
 private AiCapabilityMatrix(){}
 public record Capability(String id,String label,String grade,List<String> frameworks,String conditions,String modelVerification){ }
 public static List<Capability> entries(){return List.of(
  new Capability("DIRECT_ENV_RESPONSE","환경값의 JSON 응답 노출","VERIFIED_PATCHABLE",List.of("Deno TypeScript","Express JavaScript/TypeScript"),"원본 commit·기존 Source/Sink 필요. Deno 직접 Response.json 또는 Express ESM 기본 import app의 inline handler만 허용. 일반 상수 필드 1개 이상·AST 범위·호환성 승인 필요. Router·별칭·동적 객체는 제외.","MOCK_INTEGRATION_ONLY"),
  new Capability("LITERAL_SECURITY_SETTING","상수 보안 설정","VERIFIED_PATCHABLE",List.of("Spring .properties"),"중복·이스케이프 없는 debug/stacktrace/session cookie 상수 한 줄만 허용. 운영 설정은 별도 검증.","MOCK_INTEGRATION_ONLY"),
  new Capability("SQL_NOSQL","쿼리 입력 처리","GUIDED_REMEDIATION",List.of("기존 분석 근거에 한함"),"DB·드라이버·쿼리 의미 보존을 입증하지 못해 자동 Patch 미지원.","NOT_RUN"),
  new Capability("HTML_OUTPUT","위험한 HTML 출력","GUIDED_REMEDIATION",List.of("기존 분석 근거에 한함"),"렌더링 문맥과 인코딩 계약을 직접 확인. 획일적 문자열 치환 없음.","NOT_RUN"),
  new Capability("DESTINATION_POLICY","SSRF·경로·접근 정책","REVIEW_ONLY",List.of("기존 분석 근거에 한함"),"허용 대상과 권한 정책을 추정하지 않음. 수동 정책 확인 필요.","NOT_RUN"),
  new Capability("HARDCODED_SECRET","하드코딩 비밀정보","GUIDED_REMEDIATION",List.of("기존 Finding에 한함"),"실제 비밀값 전송 금지. 키 교체·환경변수·배포 설정은 사용자 확인 필요.","NOT_RUN"),
  new Capability("EXPRESS_PARTIAL_REVIEW","미완료 HTTP 문맥 추가 검토","REVIEW_ONLY",List.of("Worker가 등록을 확인한 Express"),"PARTIAL·미연결 지점이 있는 handler와 같은 파일 직접 함수 최대 2개. Cross-file/Next.js/Django 추가 AI 문맥 미지원.","MOCK_INTEGRATION_ONLY"),
  new Capability("NPM_LEAF_UPDATE","외부 라이브러리 업데이트","VERIFIED_PATCHABLE",List.of("루트 npm v3 lockfile leaf"),"공지 근거·허용 버전·npm 생성·두 파일 Diff·사용자 승인 필요. 런타임 호환성 미검증.","AI03_REAL_VERSION_ADVICE_ONLY_AI04_AUTOMATION_MOCK")
 );}
}
