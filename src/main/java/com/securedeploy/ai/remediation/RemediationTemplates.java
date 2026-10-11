package com.securedeploy.ai.remediation;

import com.securedeploy.ai.dto.AiConfidence;
import com.securedeploy.risk.model.FindingCategory;
import com.securedeploy.risk.model.RiskPriority;
import java.util.List;

public final class RemediationTemplates {
    private RemediationTemplates() { }
    public static RemediationContent advice(RemediationContext context) {
        if (context.priority() == RiskPriority.REVIEW_REQUIRED) {
            return new RemediationContent("실제 사용 문맥 확인이 필요합니다", context.priorityReason(),
                    "자동 판단 정보가 부족합니다. 해당 코드의 실행 여부, 외부 입력 경로, 인증/인가 및 기존 방어 처리를 먼저 확인하세요.",
                    null, null, List.of("표시된 위치와 호출 경로를 검토하고 재현 가능한 테스트를 작성하세요.",
                    "위험이 확인되면 최소 범위로 수정하고 SecureDeploy 재검사를 수행하세요."),
                    "확정 취약점이나 즉시 적용할 수정안이 아닙니다. 검토 결과를 기록하세요.", AiConfidence.LOW);
        }
        if (context.dependency() != null) {
            var dep = context.dependency();
            String action = dep.fixedVersions().isEmpty()
                    ? "저장된 수정 버전이 없습니다. 공식 advisory 및 maintainer 문서에서 해당 버전 계열의 수정 버전을 확인해야 합니다."
                    : "저장된 OSV 수정 버전 후보: " + String.join(", ", dep.fixedVersions())
                    + ". 현재 버전 계열, 런타임 및 API 호환성을 확인한 뒤 적용할 버전을 선택하세요.";
            return new RemediationContent("의존성 수정 버전과 호환성 검토", context.priorityReason(), action,
                    null, null, List.of("직접/전이 의존성과 실제 배포 scope를 확인하세요.",
                    "manifest와 lockfile을 함께 갱신하고 빌드 및 회귀 테스트를 수행하세요.",
                    "SecureDeploy 재검사에서 해당 advisory와 새 Risk Assessment를 확인하세요."),
                    "수정 버전은 모든 버전 계열에 적용되는 안전 보장이 아닙니다. EPSS는 프로젝트 해킹 확률이 아닙니다.", AiConfidence.MEDIUM);
        }
        if (context.findingCategory() == FindingCategory.SECRET) {
            boolean client = "HARDCODED_FRONTEND_SECRET".equals(context.ruleId());
            return new RemediationContent("노출 credential 제거 및 교체", "저장소나 빌드 산출물에 포함된 credential은 권한 악용으로 이어질 수 있습니다.",
                    "코드에서 credential을 제거하고 발급처에서 폐기 및 rotation하세요. Git history, 공유된 로그와 배포 산출물의 노출 여부도 확인하세요. 환경변수 또는 Secret Manager로 분리하세요.",
                    client ? "// Server-side only; never expose through VITE_*\nconst credential = process.env.SERVICE_CREDENTIAL;"
                            : "String credential = System.getenv(\"SERVICE_CREDENTIAL\");",
                    client ? null : "spring:\n  datasource:\n    password: ${DB_PASSWORD}\njwt:\n  secret: ${JWT_SECRET}",
                    List.of("기존 credential이 더 이상 유효하지 않은지 확인하세요.", "Git history 및 산출물에서 민감정보 노출 여부를 점검하세요.",
                    "환경별 Secret 주입과 로그 masking을 확인하고 SecureDeploy 재검사를 수행하세요."),
                    "예시는 서버 측 설정입니다. 프론트엔드 환경변수는 번들에 공개되므로 서버 측으로 이동해야 합니다.", AiConfidence.MEDIUM);
        }
        String rule = context.ruleId() == null ? "" : context.ruleId();
        String config = switch (rule) {
            case "DEBUG_ENABLED" -> "debug: false";
            case "STACKTRACE_EXPOSURE" -> "server:\n  error:\n    include-stacktrace: never";
            case "INSECURE_COOKIE" -> "server:\n  servlet:\n    session:\n      cookie:\n        secure: true\n        http-only: true";
            case "EXPOSED_ACTUATOR" -> "management:\n  endpoints:\n    web:\n      exposure:\n        include: health";
            default -> null;
        };
        return new RemediationContent("설정 및 코드 개선 검토", context.priorityReason(),
                config == null ? "표시된 위치에서 입력 검증, 최소 권한 및 보안 기본값을 확인하고 변경 범위를 정하세요."
                        : "운영 profile에 최소 노출 설정을 적용하고 기존 접근 제어와 충돌하지 않는지 확인하세요.",
                null, config, List.of("정상 요청과 비인가 요청을 포함한 회귀 테스트를 수행하세요.",
                "실제 배포 설정을 확인하고 SecureDeploy 재검사를 수행하세요."),
                "제공된 일부 문맥만으로 작성한 제안입니다. 적용 전 프로젝트 요구사항을 확인하세요.", AiConfidence.LOW);
    }
}
