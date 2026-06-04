package com.securedeploy.ai.service;

import com.securedeploy.ai.config.AiProviderType;
import com.securedeploy.ai.dto.AiComparisonInsightResponse;
import com.securedeploy.ai.dto.AiPriorityItemResponse;
import com.securedeploy.ai.dto.AiProjectContext;
import com.securedeploy.ai.dto.AiProjectSummaryContent;
import com.securedeploy.ai.dto.AiRemediationResponse;
import com.securedeploy.ai.dto.AiReviewRequest;
import com.securedeploy.ai.dto.AiReviewResponse;
import com.securedeploy.ai.dto.AiConfidence;
import com.securedeploy.ai.dto.AiSecurityAuditFindingResponse;
import com.securedeploy.ai.dto.AiSecurityRoadmapContent;
import com.securedeploy.ai.dto.AiRoadmapActionResponse;
import com.securedeploy.ai.dto.AiVulnerabilityFinding;
import com.securedeploy.project.dto.ReviewComparisonResponse;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.Severity;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.stereotype.Component;

@Component
public class TemplateAiProvider implements AiProvider {

    @Override
    public AiProviderType providerType() {
        return AiProviderType.TEMPLATE;
    }

    @Override
    public AiReviewResponse generateVulnerabilityReview(AiReviewRequest request, String prompt) {
        return new AiReviewResponse(
                request.ruleId(),
                titleFor(request.ruleId(), request.message()),
                descriptionFor(request),
                riskFor(request.ruleId()),
                attackScenarioFor(request.ruleId()),
                request.recommendation() + " 변경 후에는 동일한 분석을 다시 실행해 해당 ruleId가 사라졌는지 확인하세요.",
                priorityFor(request.severity())
        );
    }

    @Override
    public AiProjectSummaryContent generateProjectSummary(AiProjectContext context, String prompt) {
        if (context.findings().isEmpty()) {
            return new AiProjectSummaryContent(
                    "Rule Engine 기준으로 배포를 막을 만한 명확한 취약점은 탐지되지 않았습니다.",
                    "현재 결과에서는 특정 고위험 영역이 두드러지지 않습니다.",
                    List.of("환경변수와 운영 프로파일 설정을 실제 배포 환경에서 한 번 더 검증하세요."),
                    List.of("운영 DB 계정 권한 최소화", "HTTPS 및 보안 헤더 적용 확인", "배포 직전 SecureDeploy 재분석"),
                    "현재 점수와 탐지 결과 기준으로 배포 가능 상태에 가깝습니다. 단, 런타임 인프라 설정은 별도 점검이 필요합니다."
            );
        }

        Map<Severity, Long> severityCounts = context.findings().stream()
                .collect(Collectors.groupingBy(AiVulnerabilityFinding::severity, Collectors.counting()));
        Map<RuleCategory, Long> categoryCounts = context.findings().stream()
                .collect(Collectors.groupingBy(AiVulnerabilityFinding::category, Collectors.counting()));
        RuleCategory riskiestCategory = categoryCounts.entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElse(RuleCategory.CONFIGURATION);

        List<String> priorityFixes = context.findings().stream()
                .sorted(Comparator.comparingInt(finding -> severityRank(finding.severity())))
                .limit(5)
                .map(finding -> finding.ruleId() + " - " + finding.filePath() + ":" + finding.line() + " 수정")
                .toList();

        List<String> actions = new ArrayList<>();
        actions.add("CRITICAL/HIGH 항목을 먼저 제거한 뒤 재분석을 수행하세요.");
        actions.add("환경변수, Secret Manager, 운영 프로파일 설정이 실제 배포 환경에 주입되는지 확인하세요.");
        actions.add("인증/인가 정책과 공개 API 범위를 배포 전 수동으로 한 번 더 검토하세요.");
        if (hasCategory(context, RuleCategory.DATABASE)) {
            actions.add("데이터베이스 접근 코드는 파라미터 바인딩 또는 JPA Repository 기반으로 정리하세요.");
        }

        return new AiProjectSummaryContent(
                summaryByScore(context, severityCounts),
                riskiestCategory + " 영역에서 가장 많은 보안 신호가 탐지되었습니다.",
                priorityFixes,
                actions,
                deploymentOpinion(context)
        );
    }

    @Override
    public List<AiRemediationResponse> generateRemediationSuggestions(AiProjectContext context, String prompt) {
        return context.findings().stream()
                .sorted(Comparator.comparingInt(finding -> severityRank(finding.severity())))
                .map(this::remediationFor)
                .toList();
    }

    @Override
    public List<AiSecurityAuditFindingResponse> generateSecurityAudit(AiProjectContext context, String prompt) {
        List<AiSecurityAuditFindingResponse> findings = new ArrayList<>();
        if (hasCategory(context, RuleCategory.AUTHORIZATION)) {
            findings.add(new AiSecurityAuditFindingResponse(
                    "인가 정책 흐름 추가 검토 필요",
                    RuleCategory.AUTHORIZATION,
                    Severity.MEDIUM,
                    "Rule Engine 결과에 인가 관련 신호가 포함되어 있어 Controller와 SecurityConfig의 요청 매처 순서를 함께 확인할 필요가 있습니다.",
                    "공개 API 범위가 넓으면 인증이 필요한 API가 의도치 않게 노출될 수 있습니다.",
                    "관리자/사용자 API의 requestMatcher 범위와 method-level 권한 검증을 수동 검토하세요.",
                    AiConfidence.MEDIUM
            ));
        }
        if (hasCategory(context, RuleCategory.CONFIGURATION)) {
            findings.add(new AiSecurityAuditFindingResponse(
                    "운영 설정 분리 상태 추가 확인",
                    RuleCategory.CONFIGURATION,
                    Severity.MEDIUM,
                    "설정 파일 기반 취약점이 탐지되어 dev/prod 프로파일 분리와 운영 환경변수 주입 상태를 확인해야 합니다.",
                    "개발 설정이 운영에 반영되면 디버그 정보, actuator 정보, 오류 세부 정보가 노출될 수 있습니다.",
                    "application-prod.yml, 환경변수, 배포 매니페스트의 실제 값을 함께 점검하세요.",
                    AiConfidence.MEDIUM
            ));
        }
        if (hasCategory(context, RuleCategory.DATABASE)) {
            findings.add(new AiSecurityAuditFindingResponse(
                    "데이터 접근 계층 입력 흐름 검토",
                    RuleCategory.DATABASE,
                    Severity.HIGH,
                    "SQL 관련 탐지 결과가 있어 Controller-Service-Repository로 이어지는 입력값 전달 경로를 추가 검토해야 합니다.",
                    "입력 검증과 파라미터 바인딩이 누락되면 데이터 조회/변경 범위가 공격자에게 조작될 수 있습니다.",
                    "Repository의 파라미터 바인딩, DTO validation, service-level 권한 검사를 함께 확인하세요.",
                    AiConfidence.MEDIUM
            ));
        }
        if (findings.isEmpty() && context.securityScore() < 80) {
            findings.add(new AiSecurityAuditFindingResponse(
                    "중간 위험 항목 누적 영향 검토",
                    RuleCategory.CONFIGURATION,
                    Severity.LOW,
                    "확정 취약점 외에도 여러 낮은 위험 신호가 누적되면 운영 위험으로 이어질 수 있습니다.",
                    "개별 항목은 낮아도 배포 환경에서는 정보 노출과 접근 제어 약화가 결합될 수 있습니다.",
                    "배포 전 체크리스트로 인증, 설정, 오류 응답, 로그 노출을 한 번 더 확인하세요.",
                    AiConfidence.LOW
            ));
        }
        return findings;
    }


    @Override
    public AiComparisonInsightResponse generateComparisonInsight(ReviewComparisonResponse comparison, String prompt) {
        if (comparison.latestReviewId() == null || comparison.previousReviewId() == null) {
            return new AiComparisonInsightResponse(
                    comparison.projectId(),
                    comparison.latestReviewId(),
                    comparison.previousReviewId(),
                    "비교 가능한 분석 이력이 아직 충분하지 않습니다.",
                    "동일 프로젝트를 한 번 더 분석하면 개선 추이를 해석할 수 있습니다.",
                    "현재는 남아 있는 위험을 이전 결과와 비교할 수 없습니다.",
                    "신규 위험 여부도 아직 판단할 수 없습니다.",
                    "최소 2회 이상 분석 후 배포 준비도를 비교하는 것이 좋습니다.",
                    List.of("수정 후 같은 Project에 재분석을 실행하세요.", "이후 해결/신규/지속 취약점 변화를 확인하세요."),
                    null
            );
        }

        String improvement = comparison.scoreDiff() >= 0
                ? "보안 점수가 " + comparison.scoreDiff() + "점 개선되었습니다. 해결된 취약점 " + comparison.resolvedVulnerabilities().size() + "건을 우선 확인하세요."
                : "보안 점수가 " + Math.abs(comparison.scoreDiff()) + "점 하락했습니다. 신규 취약점과 지속 취약점을 먼저 검토해야 합니다.";
        String newRisk = comparison.newVulnerabilities().isEmpty()
                ? "새로 생긴 취약점은 없습니다. 현재 변경은 위험을 추가로 만들지는 않은 것으로 보입니다."
                : "새로 생긴 취약점 " + comparison.newVulnerabilities().size() + "건이 있습니다. 최근 수정 또는 설정 변경의 부작용일 수 있습니다.";

        return new AiComparisonInsightResponse(
                comparison.projectId(),
                comparison.latestReviewId(),
                comparison.previousReviewId(),
                "최신 분석과 직전 분석을 비교한 결과, 점수 변화는 " + comparison.scoreDiff() + "점이고 취약점 개수 변화는 " + comparison.vulnerabilityCountDiff() + "건입니다.",
                improvement,
                "지속 취약점 " + comparison.persistedVulnerabilities().size() + "건은 아직 해결되지 않은 반복 위험입니다.",
                newRisk,
                comparison.latestSecurityScore() >= 80 ? "현재 점수 기준 배포 가능에 가깝지만 지속 취약점은 배포 전 확인이 필요합니다." : "현재 점수 기준 배포 전 추가 수정이 권장됩니다.",
                List.of("지속 취약점을 먼저 제거하세요.", "신규 취약점은 최근 변경 내역과 연결해 원인을 확인하세요.", "재분석 후 점수와 취약점 개수 변화가 개선됐는지 확인하세요."),
                null
        );
    }

    @Override
    public List<AiPriorityItemResponse> generatePriorities(AiProjectContext context, String prompt) {
        List<AiVulnerabilityFinding> findings = context.findings().stream()
                .sorted(Comparator.comparingInt(finding -> severityRank(finding.severity())))
                .limit(10)
                .toList();
        List<AiPriorityItemResponse> priorities = new ArrayList<>();
        for (int i = 0; i < findings.size(); i++) {
            AiVulnerabilityFinding finding = findings.get(i);
            priorities.add(new AiPriorityItemResponse(
                    i + 1,
                    finding.ruleId(),
                    titleFor(finding.ruleId(), finding.message()),
                    finding.severity(),
                    "위험도 " + finding.severity() + ", 영역 " + finding.category() + " 기준으로 우선순위를 산정했습니다.",
                    expectedImpactFor(finding),
                    difficultyFor(finding),
                    finding.recommendation(),
                    urgencyFor(finding.severity())
            ));
        }
        return priorities;
    }

    @Override
    public AiSecurityRoadmapContent generateSecurityRoadmap(AiProjectContext context, String prompt) {
        List<String> criticalOrHighRules = context.findings().stream()
                .filter(finding -> finding.severity() == Severity.CRITICAL || finding.severity() == Severity.HIGH)
                .map(AiVulnerabilityFinding::ruleId)
                .distinct()
                .toList();
        List<String> allRules = context.findings().stream()
                .map(AiVulnerabilityFinding::ruleId)
                .distinct()
                .toList();

        return new AiSecurityRoadmapContent(
                List.of(new AiRoadmapActionResponse(
                        "고위험 취약점 즉시 제거",
                        "CRITICAL/HIGH 또는 secret/database 관련 항목을 먼저 수정하고 즉시 재분석합니다.",
                        criticalOrHighRules.isEmpty() ? allRules.stream().limit(3).toList() : criticalOrHighRules,
                        "배포 전 가장 큰 사고 가능성을 줄이기 위한 첫 단계입니다.",
                        "보안 점수 개선과 배포 위험 감소"
                )),
                List.of(new AiRoadmapActionResponse(
                        "설정과 인가 정책 정리",
                        "permitAll, actuator, debug, stacktrace, cookie 설정을 운영 기준으로 정리합니다.",
                        allRules,
                        "운영 설정 실수는 반복적으로 재발하기 쉬운 위험입니다.",
                        "재분석 시 지속 취약점 감소"
                )),
                List.of(new AiRoadmapActionResponse(
                        "배포 전 SecureDeploy 재분석",
                        "수정 후 같은 Project에 재분석을 실행하고 최신/직전 비교를 확인합니다.",
                        allRules,
                        "수정 효과와 신규 취약점 발생 여부를 확인해야 합니다.",
                        "배포 판단 근거 확보"
                )),
                List.of(new AiRoadmapActionResponse(
                        "보안 기준 자동화",
                        "CI 단계에서 SecureDeploy 분석과 Secret 관리 정책을 반복 실행하도록 준비합니다.",
                        allRules,
                        "보안 개선을 일회성 작업이 아니라 지속 관리 체계로 전환하기 위함입니다.",
                        "장기적인 보안 품질 유지"
                ))
        );
    }

    private String expectedImpactFor(AiVulnerabilityFinding finding) {
        return switch (finding.category()) {
            case SECRET_MANAGEMENT -> "민감정보 노출과 인증 정보 악용 가능성을 낮춥니다.";
            case DATABASE -> "SQL Injection과 데이터 조작 위험을 줄입니다.";
            case AUTHORIZATION, AUTHENTICATION -> "비인가 접근과 권한 우회 위험을 줄입니다.";
            case CONFIGURATION -> "운영 정보 노출과 잘못된 배포 설정 위험을 낮춥니다.";
            case INPUT_VALIDATION -> "악의적 입력으로 인한 예외와 악용 가능성을 줄입니다.";
            case FRONTEND_SECURITY -> "클라이언트 통신 설정과 배포 환경 노출 위험을 낮춥니다.";
            case CLIENT_SECRET_EXPOSURE -> "브라우저 번들과 저장소를 통한 클라이언트 민감정보 노출 가능성을 줄입니다.";
            case CLIENT_STORAGE -> "XSS 발생 시 인증 토큰이 탈취될 수 있는 영향을 줄입니다.";
            case CLIENT_XSS -> "클라이언트 XSS를 통한 세션 탈취와 악성 스크립트 실행 위험을 낮춥니다.";
            case CLIENT_REDIRECT -> "Open Redirect를 통한 피싱과 인증 흐름 악용 가능성을 줄입니다.";
            case DEPENDENCY -> "프론트엔드 공급망과 패키지 스크립트로 인한 위험을 줄입니다.";
            case DEVOPS_SECURITY -> "배포 설정과 웹 서버 구성에서 발생하는 운영 노출 위험을 줄입니다.";
            case CONTAINER_SECURITY -> "컨테이너 권한, 이미지, secret 관리 위험을 줄입니다.";
            case CI_CD_SECURITY -> "CI/CD 파이프라인의 공급망 공격과 secret 노출 가능성을 줄입니다.";
            case KUBERNETES_SECURITY -> "Kubernetes 워크로드 권한과 외부 노출 위험을 줄입니다.";
        };
    }

    private String difficultyFor(AiVulnerabilityFinding finding) {
        return switch (finding.ruleId()) {
            case "HARDCODED_PASSWORD", "HARDCODED_SECRET", "DEBUG_ENABLED", "STACKTRACE_EXPOSURE", "INSECURE_COOKIE" -> "낮음";
            case "DANGEROUS_SQL", "PERMIT_ALL_USAGE", "CORS_WILDCARD" -> "보통";
            default -> "보통";
        };
    }

    private String urgencyFor(Severity severity) {
        return switch (severity) {
            case CRITICAL -> "즉시";
            case HIGH -> "높음";
            case MEDIUM -> "보통";
            case LOW -> "낮음";
        };
    }

    private AiRemediationResponse remediationFor(AiVulnerabilityFinding finding) {
        return switch (finding.ruleId()) {
            case "HARDCODED_PASSWORD" -> response(finding,
                    "비밀번호를 환경변수로 분리",
                    "spring:\n  datasource:\n    password: hardcoded-password",
                    "spring:\n  datasource:\n    password: ${DB_PASSWORD}",
                    "DB 비밀번호는 Git 저장소와 빌드 산출물에 남지 않도록 런타임 환경변수나 Secret Manager에서 주입해야 합니다.",
                    "SecureDeploy 재분석 시 HARDCODED_PASSWORD 탐지가 사라졌는지 확인하세요.");
            case "HARDCODED_SECRET", "WEAK_JWT_SECRET" -> response(finding,
                    "JWT Secret을 강한 환경변수로 관리",
                    "jwt:\n  secret: short",
                    "jwt:\n  secret: ${JWT_SECRET}",
                    "JWT 서명키는 충분히 길고 예측 불가능해야 하며, 코드나 설정 파일에 직접 저장하지 않아야 합니다.",
                    "운영 환경의 JWT_SECRET 길이와 무작위성을 확인하고 재분석하세요.");
            case "CORS_WILDCARD" -> response(finding,
                    "CORS Origin을 신뢰 도메인으로 제한",
                    "@CrossOrigin(\"*\")",
                    "@CrossOrigin(origins = \"https://app.example.com\")",
                    "모든 Origin 허용은 브라우저 기반 API 호출 범위를 넓히므로 실제 프론트엔드 도메인만 허용해야 합니다.",
                    "@CrossOrigin(\"*\") 또는 wildcard CORS 설정이 남아 있지 않은지 확인하세요.");
            case "DANGEROUS_SQL" -> response(finding,
                    "문자열 결합 SQL 제거",
                    "String sql = \"select * from users where email = \" + email;",
                    "public interface UserRepository extends JpaRepository<User, Long> {\n    Optional<User> findByEmail(String email);\n}",
                    "사용자 입력을 SQL 문자열에 직접 결합하지 말고 JPA Repository, JPQL 파라미터, PreparedStatement 바인딩을 사용해야 합니다.",
                    "createNativeQuery, Statement, 문자열 결합 SQL 패턴이 제거됐는지 재분석하세요.");
            case "PERMIT_ALL_USAGE" -> response(finding,
                    "공개 API 범위 최소화",
                    "authorize.anyRequest().permitAll();",
                    "authorize.requestMatchers(\"/auth/login\", \"/auth/signup\").permitAll();\nauthorize.anyRequest().authenticated();",
                    "permitAll은 로그인, 회원가입, health check처럼 공개가 필요한 엔드포인트에만 제한해야 합니다.",
                    "보호 API가 permitAll 매처에 포함되지 않았는지 수동 검토하고 재분석하세요.");
            case "DEBUG_ENABLED" -> response(finding,
                    "운영 debug 비활성화",
                    "debug: true",
                    "debug: false",
                    "debug=true는 내부 설정과 디버깅 정보를 노출할 수 있으므로 운영 프로파일에서는 꺼야 합니다.",
                    "application.yml/properties의 debug 값이 false인지 확인하세요.");
            case "EXPOSED_ACTUATOR" -> response(finding,
                    "Actuator 노출 범위 제한",
                    "management.endpoints.web.exposure.include=*",
                    "management:\n  endpoints:\n    web:\n      exposure:\n        include: \"health,info\"",
                    "Actuator 전체 노출은 운영 내부 정보를 공개할 수 있으므로 필요한 엔드포인트만 허용해야 합니다.",
                    "management.endpoints.web.exposure.include=* 설정이 제거됐는지 확인하세요.");
            case "INSECURE_COOKIE" -> response(finding,
                    "쿠키 보안 속성 활성화",
                    "server.servlet.session.cookie.secure=false",
                    "server:\n  servlet:\n    session:\n      cookie:\n        secure: true\n        http-only: true",
                    "Secure와 HttpOnly 속성은 세션 쿠키 탈취 위험을 낮추는 기본 보호 장치입니다.",
                    "secure=false 또는 http-only=false 설정이 남아 있지 않은지 재분석하세요.");
            case "STACKTRACE_EXPOSURE" -> response(finding,
                    "오류 응답 stacktrace 차단",
                    "server.error.include-stacktrace=always",
                    "server:\n  error:\n    include-stacktrace: never",
                    "stacktrace는 내부 클래스명, 패키지, 파일 경로를 노출해 공격 단서를 제공할 수 있습니다.",
                    "server.error.include-stacktrace=always 설정이 제거됐는지 확인하세요.");
            default -> response(finding,
                    "탐지 항목 수정",
                    "탐지된 현재 설정",
                    finding.recommendation(),
                    "Rule Engine이 탐지한 보안 신호에 맞춰 설정과 코드를 수정해야 합니다.",
                    "수정 후 SecureDeploy 재분석으로 동일 ruleId가 사라졌는지 확인하세요.");
        };
    }

    private AiRemediationResponse response(AiVulnerabilityFinding finding, String title, String beforeExample,
                                           String afterExample, String explanation, String verification) {
        return new AiRemediationResponse(
                finding.ruleId(),
                finding.severity(),
                finding.category(),
                finding.filePath(),
                finding.line(),
                title,
                beforeExample,
                afterExample,
                explanation,
                verification
        );
    }

    private String titleFor(String ruleId, String fallback) {
        return switch (ruleId) {
            case "HARDCODED_PASSWORD" -> "하드코딩된 비밀번호 제거 필요";
            case "HARDCODED_SECRET", "WEAK_JWT_SECRET" -> "애플리케이션 시크릿 관리 개선 필요";
            case "CORS_WILDCARD" -> "CORS 허용 범위 제한 필요";
            case "DANGEROUS_SQL" -> "SQL Injection 위험 패턴 개선 필요";
            case "PERMIT_ALL_USAGE" -> "인가 정책 검토 필요";
            case "DEBUG_ENABLED" -> "운영 환경 debug 설정 비활성화 필요";
            case "EXPOSED_ACTUATOR" -> "Actuator 엔드포인트 노출 제한 필요";
            case "INSECURE_COOKIE" -> "쿠키 보안 속성 강화 필요";
            case "STACKTRACE_EXPOSURE" -> "오류 응답 내 stacktrace 노출 차단 필요";
            default -> fallback;
        };
    }

    private String descriptionFor(AiReviewRequest request) {
        return "Rule Engine이 " + request.ruleId() + " 규칙으로 " + request.category()
                + " 영역의 보안 위험을 " + request.filePath() + ":" + request.line()
                + " 위치에서 탐지했습니다. 탐지 근거는 " + safeEvidence(request.evidence()) + " 입니다.";
    }

    private String riskFor(String ruleId) {
        return switch (ruleId) {
            case "HARDCODED_PASSWORD", "HARDCODED_SECRET", "WEAK_JWT_SECRET" ->
                    "민감정보가 코드나 설정 파일에 남아 있으면 저장소 유출, 로그 노출, 배포 패키지 유출 시 인증 정보가 함께 노출될 수 있습니다.";
            case "CORS_WILDCARD" ->
                    "모든 Origin을 허용하면 신뢰하지 않는 웹 사이트에서도 브라우저를 통해 API 호출을 유도할 수 있어 데이터 노출 위험이 커집니다.";
            case "DANGEROUS_SQL" ->
                    "사용자 입력이 SQL 문자열에 결합되면 공격자가 쿼리 구조를 조작해 데이터 조회, 변경 또는 삭제를 시도할 수 있습니다.";
            case "PERMIT_ALL_USAGE" ->
                    "과도한 permitAll 설정은 인증이 필요한 API까지 공개해 비인가 접근으로 이어질 수 있습니다.";
            case "DEBUG_ENABLED", "STACKTRACE_EXPOSURE" ->
                    "디버그 정보와 stacktrace는 내부 클래스명, 경로, 설정 정보를 노출해 후속 공격의 단서가 될 수 있습니다.";
            case "EXPOSED_ACTUATOR" ->
                    "Actuator 전체 노출은 환경 정보, 메트릭, 상태 정보 등 운영 내부 정보를 외부에 공개할 수 있습니다.";
            case "INSECURE_COOKIE" ->
                    "쿠키 보안 속성이 꺼져 있으면 네트워크 탈취나 스크립트 기반 세션 탈취 위험이 증가합니다.";
            default -> "해당 탐지 결과는 배포 전 검토가 필요한 보안 위험입니다.";
        };
    }

    private String attackScenarioFor(String ruleId) {
        return switch (ruleId) {
            case "DANGEROUS_SQL" -> "공격자가 검색 파라미터에 SQL 조각을 삽입해 인증 우회 또는 데이터 덤프를 시도할 수 있습니다.";
            case "HARDCODED_PASSWORD", "HARDCODED_SECRET", "WEAK_JWT_SECRET" -> "저장소 접근 권한을 얻은 공격자가 노출된 secret으로 DB 또는 JWT 토큰을 악용할 수 있습니다.";
            case "PERMIT_ALL_USAGE" -> "외부 사용자가 인증 없이 보호되어야 할 API를 호출해 데이터에 접근할 수 있습니다.";
            case "EXPOSED_ACTUATOR" -> "공격자가 Actuator 엔드포인트를 탐색해 서비스 상태와 내부 구성을 수집할 수 있습니다.";
            default -> "공격자는 노출된 설정 또는 완화되지 않은 보안 정책을 이용해 시스템 정보를 수집하거나 접근 범위를 넓힐 수 있습니다.";
        };
    }

    private String summaryByScore(AiProjectContext context, Map<Severity, Long> severityCounts) {
        long critical = severityCounts.getOrDefault(Severity.CRITICAL, 0L);
        long high = severityCounts.getOrDefault(Severity.HIGH, 0L);
        if (critical > 0 || high > 0) {
            return "고위험 취약점이 포함되어 있어 배포 전 우선 수정이 필요합니다. 현재 보안 점수는 " + context.securityScore() + "점입니다.";
        }
        if (context.securityScore() >= 80) {
            return "전반적인 보안 상태는 양호하지만 일부 설정 또는 인가 정책 점검이 남아 있습니다.";
        }
        return "중간 수준의 보안 위험이 누적되어 있어 배포 전 개선 작업을 권장합니다.";
    }

    private String deploymentOpinion(AiProjectContext context) {
        if (context.securityScore() >= 80 && context.findings().stream().noneMatch(f -> f.severity() == Severity.CRITICAL || f.severity() == Severity.HIGH)) {
            return "AI 관점에서는 현재 탐지 결과 기준 배포 가능에 가깝지만, 운영 환경변수와 인프라 보안 설정 확인 후 배포하는 것이 좋습니다.";
        }
        if (context.securityScore() >= 60) {
            return "AI 관점에서는 조건부 배포 또는 주의 필요 상태입니다. HIGH 이상 항목과 인증/시크릿 관련 항목을 먼저 제거하세요.";
        }
        return "AI 관점에서는 배포 비권장입니다. 탐지된 취약점 수정과 재분석이 먼저 필요합니다.";
    }

    private boolean hasCategory(AiProjectContext context, RuleCategory category) {
        return context.findings().stream().anyMatch(finding -> finding.category() == category);
    }

    private String priorityFor(Severity severity) {
        return switch (severity) {
            case CRITICAL -> "즉시 수정";
            case HIGH -> "높은 우선순위";
            case MEDIUM -> "계획된 수정";
            case LOW -> "점검 권장";
        };
    }

    private int severityRank(Severity severity) {
        return switch (severity) {
            case CRITICAL -> 0;
            case HIGH -> 1;
            case MEDIUM -> 2;
            case LOW -> 3;
        };
    }

    private String safeEvidence(String evidence) {
        return evidence == null || evidence.isBlank() ? "제공되지 않음" : evidence;
    }
}
