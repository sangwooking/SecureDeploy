package com.securedeploy.project.progress;

import com.securedeploy.persistence.entity.ReviewEntity;
import com.securedeploy.review.dto.VulnerabilityResultResponse;
import com.securedeploy.risk.model.RiskAssessment;
import com.securedeploy.risk.model.RiskFinding;
import com.securedeploy.sca.model.ScaResult;
import com.securedeploy.ai.semantic.SemanticCandidate;
import com.securedeploy.ai.semantic.SemanticSnapshot;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.stream.Stream;
import org.springframework.stereotype.Component;
import static com.securedeploy.project.progress.ReviewProgressSnapshot.*;

@Component
public class ProgressComparisonEngine {
    public ReviewProgressSnapshot compare(ReviewEntity before, ReviewEntity after) {
        var entries = new ArrayList<Entry>();
        var ai = new ArrayList<AiEntry>();
        var notices = new ArrayList<String>();
        Status status;
        if (before == null) {
            status = after.getComparisonContext() != null && after.getComparisonContext().baselineReviewId() == null
                    ? Status.NO_BASELINE : Status.UNAVAILABLE;
            notices.add("비교할 이전 분석이 없거나 삭제되어 변화 여부를 판단할 수 없습니다.");
        } else {
            var previous = findings(before);
            var current = findings(after);
            var used = new HashSet<Finding>();
            for (Finding old : previous) {
                var matches = current.stream().filter(now -> matches(old, now)).toList();
                if (matches.size() == 1 && previous.stream().filter(p -> matches(p, matches.get(0))).count() == 1) {
                    Finding now = matches.get(0);
                    used.add(now);
                    entries.add(entry(changed(old, now) ? Change.CHANGED : Change.REMAINING, old, now, after,
                            "두 분석에서 같은 근거의 문제가 확인되었습니다."));
                } else {
                    boolean covered = matches.isEmpty() && covered(old, before, after)
                            && current.stream().noneMatch(now -> sameAnchor(old, now));
                    entries.add(entry(covered ? Change.RESOLVED : Change.UNAVAILABLE, old, null, after,
                            covered ? "비교 가능한 현재 분석에서 기존 문제가 더 이상 확인되지 않았습니다. 완전한 안전을 보장하지 않습니다."
                                    : "분석 범위, 조회 상태 또는 중복 근거 때문에 이번 검사에서는 확인할 수 없습니다."));
                }
            }
            for (Finding now : current) {
                if (used.contains(now)) continue;
                boolean known = covered(now, after, before) && previous.stream().noneMatch(old -> sameAnchor(old, now));
                entries.add(entry(known ? Change.NEW : Change.UNAVAILABLE, null, now, after,
                        known ? "이전 스냅샷에는 없고 이번 검사에서 발견되었습니다. 코드 수정으로 새로 생겼다는 뜻은 아닙니다."
                                : "현재 발견된 문제입니다. 이전 분석과 비교할 근거가 충분하지 않습니다."));
            }
            compareAi(before.getSemanticReview(), after.getSemanticReview(), ai);
            boolean complete = before.getRiskAssessment() != null && after.getRiskAssessment() != null
                    && compatible(before, after) && scaComparable(before) && scaComparable(after);
            status = !complete || entries.stream().anyMatch(e -> e.status() == Change.UNAVAILABLE)
                    ? Status.PARTIAL : Status.COMPLETE;
            if (before.getRiskAssessment() == null || after.getRiskAssessment() == null) status = Status.UNAVAILABLE;
            if (!complete) notices.add("분석 범위 또는 외부 조회가 불완전합니다. 확인할 수 없는 항목은 해결 수에 포함하지 않습니다.");
        }
        notices.add("새 분석 완료 시 저장한 비교입니다. 과거 분석 삭제나 외부 보안 공지 변경으로 다시 계산하지 않습니다.");
        notices.add("AI 후보의 미관찰은 취약점 해결 또는 안전 판정이 아닙니다.");
        if (after.getServerAnalysis() != null || before != null && before.getServerAnalysis() != null)
            notices.add("서버 코드 흐름 Finding은 별도 검토 항목이며 이 비교의 해결·신규 건수에 포함하지 않습니다. 분석기 버전 변경이나 미검사를 해결로 처리하지 않습니다.");
        var counts = new EnumMap<Change, Long>(Change.class);
        for (Change change : Change.values()) counts.put(change, entries.stream().filter(e -> e.status() == change).count());
        Long baseline = after.getComparisonContext() == null ? null : after.getComparisonContext().baselineReviewId();
        return new ReviewProgressSnapshot(1, after.getProject() == null ? null : after.getProject().getId(),
                before == null ? baseline : before.getId(), after.getId(), before == null ? null : before.getCreatedAt(),
                after.getCreatedAt(), Instant.now(), status,
                status == Status.COMPLETE ? "비교 가능한 분석 범위의 변화입니다." : "비교할 수 없는 범위가 있습니다. 배포 판단과 함께 확인하세요.",
                assessment(before), assessment(after), counts, List.copyOf(entries), List.copyOf(ai), notices,
                before == null ? null : before.getSourceMetadata(), after.getSourceMetadata());
    }

    public static Assessment assessment(ReviewEntity review) {
        if (review == null || review.getRiskAssessment() == null) return null;
        var risk = review.getRiskAssessment();
        return new Assessment(risk.prioritizedDeploymentAssessment(), risk.prioritySummary(),
                review.getSemanticReview() == null ? 0 : review.getSemanticReview().candidates().size(), review.getSecurityScore());
    }

    private List<Finding> findings(ReviewEntity review) {
        var risk = review.getRiskAssessment();
        if (risk == null) return List.of();
        return Stream.concat(risk.codeFindings().stream(), risk.dependencyFindings().stream())
                .map(f -> new Finding(f, review.getVulnerabilities().stream()
                        .filter(v -> f.vulnerabilityId() != null && f.vulnerabilityId().equals(v.getId()))
                        .findFirst().map(VulnerabilityResultResponse::from).orElse(null))).toList();
    }

    private boolean matches(Finding a, Finding b) {
        if (a.risk().source() != b.risk().source()) return false;
        if (a.risk().source() == RiskFinding.Source.CODE) return identity(a).equals(identity(b));
        return samePackage(a, b) && !Collections.disjoint(aliases(a), aliases(b))
                && paths(a).equals(paths(b));
    }

    private boolean sameAnchor(Finding a, Finding b) {
        if (a.risk().source() != b.risk().source()) return false;
        return a.risk().source() == RiskFinding.Source.CODE
                ? Objects.equals(a.risk().ruleId(), b.risk().ruleId()) && paths(a).equals(paths(b))
                : matches(a, b);
    }

    private boolean samePackage(Finding a, Finding b) {
        return Objects.equals(a.risk().ecosystem(), b.risk().ecosystem())
                && Objects.equals(a.risk().packageName(), b.risk().packageName());
    }

    private Set<String> aliases(Finding finding) {
        var aliases = new TreeSet<String>();
        if (finding.risk().advisoryId() != null) aliases.add(finding.risk().advisoryId().toUpperCase(Locale.ROOT));
        if (finding.risk().dependency() != null) finding.risk().dependency().aliases()
                .forEach(a -> aliases.add(a.toUpperCase(Locale.ROOT)));
        return aliases;
    }

    private Set<String> paths(Finding finding) {
        var paths = new TreeSet<String>();
        finding.risk().sourceFiles().forEach(p -> paths.add(ComparisonContextCollector.normalize(p)));
        return paths;
    }

    private String identity(Finding finding) {
        var f = finding.risk();
        String evidence = finding.code() == null ? "" : Objects.toString(finding.code().evidence(), "").replaceAll("\\s+", " ").trim();
        return f.source() + "|" + (f.source() == RiskFinding.Source.CODE
                ? f.ruleId() + "|" + paths(finding) + "|" + evidence
                : f.ecosystem() + "|" + f.packageName() + "|" + aliases(finding) + "|" + paths(finding));
    }

    private boolean compatible(ReviewEntity a, ReviewEntity b) {
        var x = a.getComparisonContext(); var y = b.getComparisonContext();
        return x != null && y != null && x.ruleAnalysisComplete() && y.ruleAnalysisComplete()
                && x.analyzerVersion() != null && x.analyzerVersion().equals(y.analyzerVersion())
                && x.schemaVersion() == y.schemaVersion() && a.getRiskAssessment() != null && b.getRiskAssessment() != null
                && Objects.equals(a.getRiskAssessment().policyVersion(), b.getRiskAssessment().policyVersion())
                && a.getRiskAssessment().assessmentCoverage().ruleEngine() == RiskAssessment.Completion.COMPLETE
                && b.getRiskAssessment().assessmentCoverage().ruleEngine() == RiskAssessment.Completion.COMPLETE;
    }

    private boolean covered(Finding finding, ReviewEntity source, ReviewEntity target) {
        if (!compatible(source, target) || paths(finding).isEmpty()
                || !target.getComparisonContext().analyzedFiles().containsAll(paths(finding))) return false;
        if (finding.risk().source() == RiskFinding.Source.DEPENDENCY) return scaComparable(source) && scaComparable(target);
        if (finding.code() == null || finding.code().evidence() == null || finding.code().evidence().isBlank()) return false;
        // Legacy catalog candidates also need dependency coverage, not merely a successful code scan.
        return finding.code().category() != com.securedeploy.rule.model.RuleCategory.DEPENDENCY
                || scaComparable(source) && scaComparable(target);
    }

    private boolean scaComparable(ReviewEntity review) {
        var sca = review.getScaResult();
        return sca != null && sca.status() == ScaResult.Status.COMPLETE
                && sca.summary().unresolvedDependencies() == 0 && sca.warnings().isEmpty()
                && sca.summary().dependenciesAnalyzed() == sca.summary().dependenciesDiscovered()
                && review.getRiskAssessment() != null
                && review.getRiskAssessment().assessmentCoverage().sca() == RiskAssessment.Completion.COMPLETE;
    }

    private boolean changed(Finding a, Finding b) {
        if (a.risk().priority() != b.risk().priority() || !Objects.equals(a.risk().version(), b.risk().version())) return true;
        if (a.code() != null && b.code() != null) return a.code().severity() != b.code().severity()
                || a.code().confidence() != b.code().confidence() || a.code().falsePositiveRisk() != b.code().falsePositiveRisk();
        return a.risk().dependency() != null && b.risk().dependency() != null
                && (!Objects.equals(a.risk().dependency().fixedVersions(), b.risk().dependency().fixedVersions())
                || !Objects.equals(a.risk().dependency().severity(), b.risk().dependency().severity()));
    }

    private Entry entry(Change change, Finding before, Finding after, ReviewEntity current, String note) {
        var finding = after == null ? before : after;
        var versions = current.getScaResult() == null || finding.risk().source() != RiskFinding.Source.DEPENDENCY ? List.<String>of()
                : current.getScaResult().components().stream().filter(c -> c.ecosystem().name().equals(finding.risk().ecosystem())
                && c.packageName().equals(finding.risk().packageName()) && paths(finding).contains(ComparisonContextCollector.normalize(c.sourceFile())))
                .map(c -> Objects.toString(c.version(), "미확정")).distinct().sorted().toList();
        return new Entry(hash(identity(finding)), change, before, after, versions, note);
    }

    private void compareAi(SemanticSnapshot before, SemanticSnapshot after, List<AiEntry> result) {
        List<SemanticCandidate> old = before == null ? List.of() : before.candidates();
        List<SemanticCandidate> now = after == null ? List.of() : after.candidates();
        var used = new HashSet<SemanticCandidate>();
        for (var candidate : old) {
            var matches = now.stream().filter(c -> aiIdentity(c).equals(aiIdentity(candidate))).toList();
            var matched = matches.size() == 1 && old.stream().filter(c -> aiIdentity(c).equals(aiIdentity(candidate))).count() == 1 ? matches.get(0) : null;
            if (matched != null) used.add(matched);
            AiChange change = matched != null ? AiChange.REMAINING : matches.isEmpty() && aiCovered(candidate, before, after)
                    ? AiChange.NOT_REOBSERVED : AiChange.UNAVAILABLE;
            result.add(new AiEntry(hash(aiIdentity(candidate)), change, candidate, matched,
                    change == AiChange.NOT_REOBSERVED ? "이번 AI 검토에서는 다시 관찰되지 않았습니다. 해결 또는 안전 판정이 아닙니다."
                            : "AI 추가 확인 항목의 변화이며 확정 취약점 수에 포함하지 않습니다."));
        }
        for (var candidate : now) if (!used.contains(candidate)) result.add(new AiEntry(hash(aiIdentity(candidate)),
                aiCovered(candidate, after, before) && old.stream().noneMatch(c -> aiIdentity(c).equals(aiIdentity(candidate)))
                        ? AiChange.NEW : AiChange.UNAVAILABLE, null, candidate, "현재 AI 검토의 추가 확인 후보입니다."));
    }

    private boolean aiCovered(SemanticCandidate candidate, SemanticSnapshot source, SemanticSnapshot target) {
        if (source == null || target == null || source.semanticReviewStatus() != SemanticSnapshot.Status.COMPLETED
                || target.semanticReviewStatus() != SemanticSnapshot.Status.COMPLETED || source.omittedSlices() > 0 || target.omittedSlices() > 0
                || !Objects.equals(source.promptVersion(), target.promptVersion()) || !Objects.equals(source.model(), target.model())) return false;
        return !candidate.evidence().isEmpty() && candidate.evidence().stream().allMatch(e -> target.slices().stream()
                .flatMap(s -> s.locations().stream()).anyMatch(l -> Objects.equals(e.filePath(), l.filePath())
                        && e.functionName() != null && Objects.equals(e.functionName(), l.functionName())));
    }

    private String aiIdentity(SemanticCandidate c) {
        return c.candidateType() + "|" + c.evidence().stream().map(e -> ComparisonContextCollector.normalize(e.filePath())
                + "|" + Objects.toString(e.functionName(), "")).distinct().sorted().toList();
    }

    private String hash(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception impossible) { throw new IllegalStateException("Cannot fingerprint comparison"); }
    }
}
