package com.securedeploy.sca.service;

import com.securedeploy.auth.service.CurrentUserService;
import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.persistence.service.ReviewPersistenceService;
import com.securedeploy.risk.model.RiskFinding;
import com.securedeploy.sca.client.VulnerabilityDataSource;
import com.securedeploy.sca.config.ScaProperties;
import com.securedeploy.sca.dto.*;
import com.securedeploy.sca.dto.SupplementalDependencyResponse.Status;
import com.securedeploy.sca.model.*;
import com.securedeploy.sca.parser.VersionClassifier;
import java.time.Instant;
import java.util.*;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
public class SupplementalDependencyService {
    private final ReviewPersistenceService reviews;
    private final CurrentUserService currentUser;
    private final VulnerabilityDataSource dataSource;
    private final ScaProperties properties;
    private final Map<Long, Window> windows = new HashMap<>();
    private final Set<Long> active = new HashSet<>();

    public SupplementalDependencyService(ReviewPersistenceService reviews, CurrentUserService currentUser,
            VulnerabilityDataSource dataSource, ScaProperties properties) {
        this.reviews = reviews;
        this.currentUser = currentUser;
        this.dataSource = dataSource;
        this.properties = properties;
    }

    // A read-only supplement: never save, reassess, or attach user assertions to a review.
    public SupplementalDependencyResponse lookup(Long reviewId, SupplementalDependencyRequest request) {
        Long userId = currentUser.currentUserId();
        var review = reviews.findReviewDetail(reviewId, userId);
        var risk = review.riskAssessment();
        var finding = risk == null ? null : risk.reviewRequirements().stream()
                .filter(f -> f.findingId().equals(request.findingId()) && f.source() == RiskFinding.Source.DEPENDENCY
                        && "UNRESOLVED_VERSION".equals(f.reasonCode()) && f.dependency() == null)
                .findFirst().orElse(null);
        if (finding == null) throw invalid("정보가 부족한 라이브러리 분석 항목에서만 추가 조회할 수 있습니다.");
        ScaEcosystem ecosystem;
        try { ecosystem = ScaEcosystem.valueOf(finding.ecosystem()); }
        catch (RuntimeException exception) { throw invalid("라이브러리 유형을 확인하지 못했습니다. 프로젝트를 다시 검사해 주세요."); }
        String name = request.packageName().strip(), version = request.version().strip();
        var component = VersionClassifier.component(ecosystem, name, version, null, null, "user-provided", 0);
        if (name.length() > 256 || version.length() > 128 || component.versionResolution() != VersionResolution.EXACT
                || !component.packageName().equals(name) || !component.version().equals(version)
                || Set.of("unknown", "null", "n/a").contains(name.toLowerCase(Locale.ROOT))) {
            throw invalid(ecosystem == ScaEcosystem.MAVEN
                    ? "라이브러리 이름은 그룹:이름 형식으로, 버전은 범위나 변수 없는 정확한 값으로 입력해 주세요."
                    : "라이브러리 이름과 정확한 버전을 입력해 주세요. 주소·스크립트·버전 범위는 사용할 수 없습니다.");
        }
        String knownName = finding.packageName();
        if (knownName != null && !knownName.startsWith("<") && !knownName.equals(name)) {
            throw invalid("소스에서 확인된 라이브러리 이름은 변경할 수 없습니다.");
        }
        if (!properties.enabled()) return response(Status.DISABLED, component, List.of());
        begin(userId);
        try {
            var result = dataSource.lookup(List.of(component));
            Status status = result.incomplete() || !result.analyzedIdentities().contains(component.identity())
                    ? result.findings().isEmpty() ? Status.UNAVAILABLE : Status.PARTIAL : Status.COMPLETE;
            return response(status, component, result.findings());
        } catch (RuntimeException exception) {
            // Do not log user input or an upstream body, including on transport/parse failure.
            return response(Status.UNAVAILABLE, component, List.of());
        } finally { end(userId); }
    }

    private SupplementalDependencyResponse response(Status status, DependencyComponent c, List<DependencyVulnerability> findings) {
        return new SupplementalDependencyResponse("USER_PROVIDED", status, Instant.now(), c.ecosystem(), c.packageName(), c.version(), findings);
    }

    // Bound memory and concurrent work in addition to the existing OSV time/response/request budgets.
    private synchronized void begin(Long userId) {
        long now = System.nanoTime();
        windows.entrySet().removeIf(e -> now - e.getValue().start >= 60_000_000_000L);
        var window = windows.get(userId);
        if (active.contains(userId) || active.size() >= 4 || (window != null && window.count >= 6)
                || (window == null && windows.size() >= 10_000)) {
            throw new SecureDeployException(HttpStatus.TOO_MANY_REQUESTS, "추가 조회가 진행 중이거나 요청이 많습니다. 잠시 후 다시 확인해 주세요.");
        }
        windows.put(userId, new Window(window == null ? now : window.start, window == null ? 1 : window.count + 1));
        active.add(userId);
    }
    private synchronized void end(Long userId) { active.remove(userId); }
    private record Window(long start, int count) { }
    private SecureDeployException invalid(String message) { return new SecureDeployException(HttpStatus.BAD_REQUEST, message); }
}
