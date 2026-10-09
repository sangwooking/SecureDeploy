package com.securedeploy.risk.policy;

public enum RiskReason {
    KNOWN_EXPLOITED_VULNERABILITY("정확한 취약 버전에 연결된 CVE가 CISA KEV에 등재되어 실제 공격에서 악용된 사실이 확인되었습니다. 배포 전 조치가 필요합니다. 이 프로젝트가 공격받았다는 의미는 아닙니다."),
    HIGH_EXPLOIT_PROBABILITY("정확한 취약 버전에서 높은 기술적 심각도와 정책 기준 이상의 EPSS score·percentile이 함께 확인되어 배포 전 조치가 필요합니다. 프로젝트별 침해 확률은 아닙니다."),
    INCOMPLETE_THREAT_INTELLIGENCE("일부 CVE의 최신 악용 정보를 확인하지 못해 우선순위가 높아질 가능성을 배제할 수 없습니다. 기존 조치 우선순위는 유지하며 추가 검토가 필요합니다."),
    MISSING_METADATA("신뢰도, 오탐 가능성 또는 판단 근거가 누락되어 자동 우선순위를 확정할 수 없습니다."),
    UNCERTAIN_FINDING("탐지 신뢰도가 낮거나 오탐 가능성이 높아 실제 사용 문맥을 확인해야 합니다. 자동 배포 차단 근거로 사용하지 않았습니다."),
    PATTERN_REQUIRES_CONTEXT("패턴은 발견되었지만 입력 흐름·권한·실행 문맥을 확인하지 못했습니다. 실제 공격 가능성을 추가 검토해야 합니다."),
    CONFIRMED_SECRET("정적 분석에서 하드코딩 credential 패턴의 신뢰도가 높고 오탐 가능성이 낮습니다. 실제 사용 여부 확인과 분리·교체를 배포 전에 완료해야 합니다. 키 유효성은 검증하지 않았습니다."),
    STRONG_CONFIGURATION("높은 신뢰도로 위험 설정이 확인되어 배포 전 수정이 필요합니다. 운영 사용 여부는 별도로 확인해야 합니다."),
    CODE_FIX_RECOMMENDED("현재 탐지 근거에 따라 배포 전 수정을 권장합니다. 심각도만으로 자동 차단하지 않았습니다."),
    CODE_INFORMATIONAL("낮은 심각도의 신뢰 가능한 개선 항목입니다. 운영 문맥에 맞게 검토하세요."),
    UNRESOLVED_VERSION("의존성 버전을 확정할 수 없어 취약 여부를 자동으로 판단할 수 없습니다."),
    INCOMPLETE_SCA("SCA가 완료되지 않았거나 조회 근거가 불충분합니다. 미조회 항목을 안전하다고 판단할 수 없습니다."),
    UNKNOWN_DEPENDENCY_SEVERITY("취약점이 반환되었지만 심각도와 유효한 CVSS 점수를 확인할 수 없어 검토가 필요합니다."),
    CRITICAL_DEPENDENCY("정확한 선언/lock 버전에 대해 OSV 조회가 완료되어 Critical 취약점이 확인되었습니다. 배포 전 업데이트 또는 위험 해소 검토가 필요합니다. 실제 설치·도달 가능성은 검증하지 않았습니다."),
    DEPENDENCY_FIX_RECOMMENDED("정확한 버전에 알려진 취약점이 확인되어 배포 전 업데이트를 권장합니다. 도달 가능성 미확인 상태이므로 High 심각도만으로 차단하지 않았습니다."),
    DEPENDENCY_INFORMATIONAL("정확한 버전에서 Low 취약점이 확인되었습니다. 간접 의존성도 안전하다고 간주하지 않으며 업데이트를 검토해야 합니다.");

    private final String message;
    RiskReason(String message) { this.message = message; }
    public String message() { return message; }
}
