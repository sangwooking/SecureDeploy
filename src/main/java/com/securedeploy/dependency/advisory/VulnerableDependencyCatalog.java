package com.securedeploy.dependency.advisory;

import com.securedeploy.dependency.model.DependencyEcosystem;
import com.securedeploy.dependency.model.DependencyInfo;
import com.securedeploy.dependency.model.VulnerableDependencyInfo;
import com.securedeploy.rule.model.Severity;
import java.util.Locale;
import java.util.Optional;

public class VulnerableDependencyCatalog {

    public Optional<VulnerableDependencyInfo> findVulnerability(DependencyInfo dependency) {
        return switch (dependency.ecosystem()) {
            case NPM -> findNpm(dependency);
            case MAVEN, GRADLE -> findJavaDependency(dependency);
            case DOCKER -> findDockerImage(dependency);
        };
    }

    private Optional<VulnerableDependencyInfo> findNpm(DependencyInfo dependency) {
        String name = normalizeName(dependency.name());
        String version = dependency.version();
        if ("event-stream".equals(name) && VersionComparator.isLessThanOrEqual(version, "3.3.6")) {
            return vulnerable(dependency, null, Severity.HIGH, "공급망 공격 이력이 있는 event-stream 취약 버전 후보입니다.", "event-stream 사용을 제거하거나 신뢰 가능한 대체 패키지로 교체하고 lockfile을 재생성하세요.");
        }
        if ("lodash".equals(name) && VersionComparator.isLessThan(version, "4.17.21")) {
            return vulnerable(dependency, "4.17.21", Severity.HIGH, "lodash 현재 버전은 Prototype Pollution 계열 취약점 위험이 있는 알려진 취약 버전 후보입니다.", "lodash를 4.17.21 이상으로 업데이트하는 것을 권장합니다.");
        }
        if ("minimist".equals(name) && VersionComparator.isLessThan(version, "1.2.6")) {
            return vulnerable(dependency, "1.2.6", Severity.MEDIUM, "minimist 현재 버전은 Prototype Pollution 취약점 위험이 있는 버전 후보입니다.", "minimist를 1.2.6 이상으로 업데이트하고 의존성 트리를 재검토하세요.");
        }
        if ("axios".equals(name) && VersionComparator.isLessThan(version, "0.21.1")) {
            return vulnerable(dependency, "0.21.1", Severity.MEDIUM, "axios 현재 버전은 SSRF/보안 우회 등 알려진 취약점 영향을 받을 수 있는 오래된 버전 후보입니다.", "axios를 0.21.1 이상, 가능하면 최신 안정 버전으로 업데이트하세요.");
        }
        if ("serialize-javascript".equals(name) && VersionComparator.isLessThan(version, "3.1.0")) {
            return vulnerable(dependency, "3.1.0", Severity.HIGH, "serialize-javascript 현재 버전은 XSS 관련 취약점 위험이 있는 버전 후보입니다.", "serialize-javascript를 3.1.0 이상으로 업데이트하고 직렬화된 HTML 삽입 경로를 점검하세요.");
        }
        return Optional.empty();
    }

    private Optional<VulnerableDependencyInfo> findJavaDependency(DependencyInfo dependency) {
        String name = normalizeName(dependency.name());
        String artifact = artifactName(name);
        String version = dependency.version();
        if ("log4j-core".equals(artifact) && VersionComparator.isLessThan(version, "2.17.1")) {
            return vulnerable(dependency, "2.17.1", Severity.HIGH, "log4j-core 현재 버전은 Log4Shell 계열 취약점 위험이 있는 버전 후보입니다.", "log4j-core를 2.17.1 이상으로 업데이트하고 transitive dependency도 함께 확인하세요.");
        }
        if ("spring-webmvc".equals(artifact) && VersionComparator.isLessThan(version, "5.3.18")) {
            return vulnerable(dependency, "5.3.18", Severity.HIGH, "spring-webmvc 현재 버전은 알려진 Spring Framework 취약점 영향을 받을 수 있는 오래된 버전 후보입니다.", "spring-webmvc를 5.3.18 이상 또는 현재 Spring Boot BOM이 권장하는 안정 버전으로 업데이트하세요.");
        }
        if ("jackson-databind".equals(artifact) && VersionComparator.isLessThan(version, "2.13.4")) {
            return vulnerable(dependency, "2.13.4", Severity.HIGH, "jackson-databind 현재 버전은 역직렬화 관련 취약점 위험이 있는 오래된 버전 후보입니다.", "jackson-databind를 2.13.4 이상으로 업데이트하고 polymorphic deserialization 사용 여부를 점검하세요.");
        }
        if ("commons-collections".equals(artifact) && VersionComparator.isLessThan(version, "3.2.2")) {
            return vulnerable(dependency, "3.2.2", Severity.HIGH, "commons-collections 현재 버전은 Java 역직렬화 공격 체인에 악용될 수 있는 취약 버전 후보입니다.", "commons-collections를 3.2.2 이상으로 업데이트하거나 필요하지 않다면 제거하세요.");
        }
        return Optional.empty();
    }

    private Optional<VulnerableDependencyInfo> findDockerImage(DependencyInfo dependency) {
        String image = normalizeName(dependency.name());
        String tag = dependency.version() == null ? "latest" : dependency.version().toLowerCase(Locale.ROOT);
        if ("latest".equals(tag) && ("node".equals(image) || "openjdk".equals(image) || "nginx".equals(image))) {
            return vulnerable(dependency, null, Severity.MEDIUM, "Docker base image에 latest 태그가 사용되어 재현 불가능한 빌드와 예기치 않은 취약 버전 도입 위험이 있습니다.", "운영 이미지는 고정 버전 또는 digest pinning을 사용하고 정기적으로 이미지 스캔을 수행하세요.");
        }
        if ("ubuntu".equals(image) && "18.04".equals(tag)) {
            return vulnerable(dependency, "22.04 또는 24.04 LTS", Severity.MEDIUM, "ubuntu:18.04는 오래된 base image 후보이며 보안 업데이트와 패키지 취약점 위험이 커질 수 있습니다.", "ubuntu 22.04/24.04 LTS 등 지원 중인 base image로 전환하고 이미지 스캔을 수행하세요.");
        }
        if ("alpine".equals(image) && VersionComparator.isLessThanOrEqual(tag, "3.12")) {
            return vulnerable(dependency, "3.18 이상", Severity.MEDIUM, "alpine 3.12 이하 이미지는 오래된 패키지를 포함할 가능성이 높은 base image 후보입니다.", "alpine 최신 안정 버전으로 업데이트하고 런타임 패키지 취약점을 재점검하세요.");
        }
        return Optional.empty();
    }

    private Optional<VulnerableDependencyInfo> vulnerable(DependencyInfo dependency, String safeVersion, Severity severity, String advisory, String recommendation) {
        return Optional.of(new VulnerableDependencyInfo(
                dependency.name(),
                dependency.version(),
                safeVersion,
                dependency.ecosystem(),
                severity,
                null,
                advisory,
                recommendation
        ));
    }

    private String normalizeName(String name) {
        if (name == null) {
            return "";
        }
        String normalized = name.strip().toLowerCase(Locale.ROOT);
        int slash = normalized.lastIndexOf('/');
        if (normalized.contains(":")) {
            return normalized;
        }
        if (slash >= 0 && !normalized.startsWith("@")) {
            normalized = normalized.substring(slash + 1);
        }
        return normalized;
    }

    private String artifactName(String name) {
        int colon = name.lastIndexOf(':');
        return colon >= 0 ? name.substring(colon + 1) : name;
    }
}
