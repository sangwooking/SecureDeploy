package com.securedeploy.analysis.deployment;

import java.util.*;

final class DeploymentGuidance {
    private DeploymentGuidance() { }
    static final Map<String, List<String>> TEXT = Map.ofEntries(
        Map.entry("CI_UNTRUSTED_PR_EXECUTION",List.of("외부 PR 코드와 권한 있는 실행 선언이 연결됩니다","pull_request_target·PR head checkout·저장된 token 권한 또는 secret 전달 선언과 프로젝트 실행을 연결했습니다. 실제 권한·secret 존재·승인·공격 성공은 미검증입니다 (CWE-829).","미승인 PR 코드는 권한·배포 secret이 없는 별도 작업에서 검사하세요. trusted base 코드와 권한 작업을 분리하고 필요한 permissions만 지정하세요. checkout의 자격증명 보존과 실행 순서를 함께 검토하세요.")),
        Map.entry("CI_SCRIPT_EXPRESSION",List.of("요청자가 정할 수 있는 값이 CI 실행 스크립트에 삽입됩니다","이벤트 텍스트 표현식이 run 스크립트 생성 과정에 직접 포함됩니다. 실제 입력값·실행·공격 성공은 확인하지 않았습니다 (CWE-78).","GitHub 표현식을 run 문자열에 직접 삽입하지 말고 env에 데이터로 전달한 뒤 인수를 따옴표로 감싸세요. env 분리 후에도 eval·간접 shell 실행을 사용하면 다시 위험해질 수 있습니다. 로컬 정적 검토와 정상 작업을 확인하세요.")),
        Map.entry("COMPOSE_SOCKET", List.of("컨테이너에 Docker 제어 소켓을 연결합니다", "소켓을 통해 호스트의 컨테이너를 제어할 가능성이 있습니다. 읽기 전용 마운트만으로 API 호출을 차단한다고 보증하지 않습니다.", "소켓 연결을 제거하거나 필요한 작업만 허용하는 별도 중계 서비스를 검토하세요.")),
        Map.entry("COMPOSE_CAPABILITY", List.of("컨테이너에 넓은 시스템 권한을 추가합니다", "추가된 권한으로 컨테이너 격리 효과가 약해질 수 있습니다.", "cap_add를 줄이고 실제 필요한 권한만 허용하세요.")),
        Map.entry("COMPOSE_PORT_BINDING", List.of("서비스 포트를 넓은 주소 범위에 공개하는 선언입니다", "호스트 바인딩이 생략되었거나 전체 주소로 지정됐습니다. 방화벽·실제 외부 접근은 확인하지 않았습니다.", "외부 공개가 필요 없다면 loopback 또는 필요한 인터페이스만 바인딩하고 방화벽을 확인하세요.")),
        Map.entry("COMPOSE_ROOT_OVERRIDE", List.of("실행 사용자를 root로 지정합니다", "이 서비스의 user 선언은 이미지의 기본 USER를 바꿀 수 있습니다. 실제 실행 여부와 다른 override는 미확인입니다.", "필요한 파일 권한을 준비한 뒤 non-root UID를 지정하고 배포 구성을 확인하세요.")),
        Map.entry("COMPOSE_HOST_MOUNT", List.of("호스트의 중요 경로를 컨테이너에 연결합니다", "호스트 파일이나 장치에 접근할 가능성이 있습니다. 읽기 전용 여부와 컨테이너 내부 권한도 확인해야 합니다.", "마운트 경로를 필요한 하위 디렉터리로 제한하고 가능한 경우 읽기 전용으로 지정하세요.")),
        Map.entry("COMPOSE_SECURITY_DISABLED", List.of("컨테이너 보안 제한을 해제하는 선언입니다", "기본 보안 프로파일이나 권한 상승 방지가 비활성화될 수 있습니다.", "unconfined 또는 no-new-privileges=false 사용 이유를 확인하고 필요한 제한을 복원하세요.")),
        Map.entry("DJANGO_DEBUG", List.of("오류 상세 정보를 표시하도록 설정되어 있습니다", "DEBUG=True 선언을 확인했습니다. 운영에서 이 모듈이 활성화되면 내부 정보가 노출될 수 있습니다.", "운영에 적용되는 settings 모듈을 확인한 뒤 DEBUG=False로 설정하세요. 개발 환경과 분리하세요.")),
        Map.entry("DJANGO_SECRET_LITERAL", List.of("Django 비밀값이 소스에 직접 선언되어 있습니다", "SECRET_KEY의 비어 있지 않은 문자열 선언입니다. 실제 운영 사용이나 키의 진위는 확인하지 않았으며 값은 저장하지 않습니다.", "환경별 비밀 저장소로 이동하세요. 실제 사용된 키가 노출됐다면 교체 영향과 세션 무효화를 검토하세요.")),
        Map.entry("DJANGO_ALLOWED_HOSTS", List.of("모든 호스트 이름을 허용합니다", "ALLOWED_HOSTS에 *가 선언되어 있습니다. 별도 Host 검증과 적용 환경은 미확인입니다.", "실제 서비스 도메인만 허용하고 프록시와 Host 검증 동작을 확인하세요.")),
        Map.entry("DJANGO_SECURE_COOKIE", List.of("쿠키를 HTTPS에만 제한하지 않는 설정입니다", "secure 쿠키 플래그가 False입니다. 실제 HTTPS 배포 및 프록시 설정은 미확인입니다.", "운영 HTTPS 환경에서 SESSION_COOKIE_SECURE와 CSRF_COOKIE_SECURE를 활성화하고 로그인·CSRF 흐름을 테스트하세요.")),
        Map.entry("DJANGO_HTTPS", List.of("Django의 HTTPS 강제 설정이 비활성화되어 있습니다", "애플리케이션의 HTTPS 리다이렉트 또는 HSTS 설정을 비활성화하는 선언입니다. 외부 프록시의 보호 여부는 모릅니다.", "프록시의 HTTPS 처리와 중복 리다이렉트를 확인한 뒤 환경에 맞게 설정하세요. HSTS는 하위 도메인 영향까지 검토하세요."))
    );
    static List<DeploymentSnapshot.Finding> findings(List<DeploymentSnapshot.FileResult> files) {
        var result = new LinkedHashMap<String, DeploymentSnapshot.Finding>();
        for (var f : files) for (var o : f.observations()) {
            var text = TEXT.get(o.ruleId());
            if (text == null || !"STATIC".equals(o.valueStatus())) continue;
            String identity = f.filePath() + "|" + o.scope() + "|" + o.setting() + "|" + o.line() + "|" + o.ruleId();
            String id = "config:" + UUID.nameUUIDFromBytes(identity.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            result.putIfAbsent(id, new DeploymentSnapshot.Finding(id, "DEPLOYMENT_CONFIGURATION", "REVIEW_REQUIRED", "NOT_COMPARED",
                    f.filePath(), o.line(), o.scope(), o.setting(), o.ruleId(), o.valueSummary(), text.get(0), text.get(1), text.get(2),
                    List.of("실제 배포에서 선택하는 환경·서비스·추가 설정 파일을 확인하세요.", "변경 후 기능과 배포 설정을 테스트하고 같은 프로젝트를 다시 검사하세요.")));
            if (result.size() >= 300) return List.copyOf(result.values());
        }
        return List.copyOf(result.values());
    }
}
