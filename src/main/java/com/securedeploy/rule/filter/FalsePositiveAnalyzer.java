package com.securedeploy.rule.filter;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.project.model.ProjectFileType;
import com.securedeploy.project.model.ProjectStructure;
import com.securedeploy.rule.model.DetectionConfidence;
import com.securedeploy.rule.model.FalsePositiveRisk;
import com.securedeploy.rule.model.RuleMatch;
import com.securedeploy.rule.model.Severity;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.springframework.stereotype.Component;

@Component
public class FalsePositiveAnalyzer {

    private static final Set<String> TARGET_RULE_IDS = Set.of(
            "HARDCODED_SECRET",
            "HARDCODED_PASSWORD",
            "HARDCODED_FRONTEND_SECRET",
            "DOCKER_SECRET_ENV",
            "K8S_SECRET_PLAIN_TEXT",
            "GITHUB_ACTIONS_SECRET_ECHO",
            "LOCAL_STORAGE_TOKEN",
            "REACT_DANGEROUS_HTML"
    );
    private static final Set<String> SECRET_RULE_IDS = Set.of(
            "HARDCODED_SECRET",
            "HARDCODED_PASSWORD",
            "HARDCODED_FRONTEND_SECRET",
            "DOCKER_SECRET_ENV",
            "K8S_SECRET_PLAIN_TEXT",
            "GITHUB_ACTIONS_SECRET_ECHO"
    );
    private static final Pattern API_KEY_PATTERN = Pattern.compile("(?i)(sk-[a-z0-9_-]{16,}|ghp_[a-z0-9_]{20,}|xoxb-[a-z0-9-]{20,}|akia[0-9a-z]{16}|aiza[0-9a-z_-]{20,})");
    private static final Pattern JWT_PATTERN = Pattern.compile("(?i)eyJ[a-z0-9_-]+\\.[a-z0-9_-]+\\.[a-z0-9_-]+");
    private static final Pattern DATA_URL_PATTERN = Pattern.compile("(?i)data:(?:image/(?:png|jpeg|jpg|gif|webp|svg\\+xml)|application/octet-stream);base64,");
    private static final Pattern DUMMY_PATTERN = Pattern.compile(
            "(?i)^(?:dummy(?:[-_].*)?|example(?:[-_].*)?|test(?:[-_].*)?|change[-_]?me(?:[-_].*)?|your[-_](?:api[-_]?key|secret|token|key|password)(?:[-_].*)?|placeholder(?:[-_].*)?|localhost|password)$"
    );
    private static final Pattern ASSIGNED_VALUE_PATTERN = Pattern.compile(
            "(?i)[a-z_$][a-z0-9_$.-]*\\s*(?:=|:)\\s*[\\\"']?([^\\s\\\"'#;,]+)"
    );
    private static final Pattern EXECUTION_CONTEXT_PATTERN = Pattern.compile("(?i)(eval\\s*\\(|new\\s+Function\\s*\\(|dangerouslySetInnerHTML|innerHTML\\s*=|document\\.write\\s*\\(|atob\\s*\\(|window\\.location\\.href|location\\.assign)");
    private static final Pattern STATIC_DATA_NAME_PATTERN = Pattern.compile("(?i)(image|img|data|model|dataset|sample|mock|fixture|avatar|png|jpeg|base64)");
    private static final Pattern BASE64_CHARS = Pattern.compile("^[A-Za-z0-9+/=_-]+$");

    public List<RuleMatch> analyze(ProjectStructure projectStructure, List<RuleMatch> matches) {
        Map<String, ProjectFile> filesByPath = projectStructure.analysisFiles().stream()
                .collect(Collectors.toMap(ProjectFile::relativePath, Function.identity(), (first, ignored) -> first));
        Map<FindingIdentity, RuleMatch> analyzedMatches = new LinkedHashMap<>();

        for (RuleMatch match : matches) {
            ProjectFile file = filesByPath.get(match.filePath());
            String sourceLine = sourceLine(file, match.line());
            FalsePositiveDecision decision = decide(new FalsePositiveContext(match, file, sourceLine));
            if (decision.action() == FalsePositiveAction.EXCLUDE) {
                continue;
            }
            RuleMatch analyzed = match.withFalsePositiveAnalysis(
                    decision.severity(),
                    decision.falsePositiveRisk(),
                    decision.confidence(),
                    decision.analysisNote()
            );
            analyzedMatches.putIfAbsent(FindingIdentity.from(analyzed), analyzed);
        }
        return List.copyOf(analyzedMatches.values());
    }

    private FalsePositiveDecision decide(FalsePositiveContext context) {
        RuleMatch match = context.match();
        if (!TARGET_RULE_IDS.contains(match.ruleId())) {
            return FalsePositiveDecision.keep(match.severity(), FalsePositiveRisk.LOW, DetectionConfidence.HIGH, "명확한 룰 패턴에 의해 탐지되었습니다.");
        }

        String path = lower(match.filePath());
        String evidence = nullToEmpty(match.evidence());
        String sourceLine = nullToEmpty(context.sourceLine());
        String combined = evidence + "\n" + sourceLine;
        boolean secretRule = SECRET_RULE_IDS.contains(match.ruleId());
        boolean executionContext = hasExecutionContext(sourceLine) || hasExecutionContext(evidence);
        boolean knownCredentialPattern = hasStrongCredentialPattern(sourceLine) || hasStrongCredentialPattern(evidence);
        boolean highEntropyCredential = hasLongHighEntropyCredential(sourceLine);
        boolean strongCredential = knownCredentialPattern || highEntropyCredential;

        if (secretRule && isLockFile(context.file(), path) && looksLikeLockfileIntegrity(sourceLine + "\n" + evidence)) {
            return FalsePositiveDecision.exclude("lock file의 integrity/resolved hash로 보여 secret 탐지에서 제외했습니다. 의존성 분석 룰은 별도로 유지됩니다.");
        }
        if (secretRule && isGeneratedNoisePath(path)) {
            return FalsePositiveDecision.exclude("dist/build/node_modules/coverage 같은 생성 산출물 경로에서 발견되어 secret 탐지에서 제외했습니다.");
        }
        if (secretRule && isBase64DataUrl(combined) && !executionContext) {
            return FalsePositiveDecision.exclude("base64 이미지 또는 정적 data URL로 보이며 실행/렌더링 위험 문맥이 없어 secret 탐지에서 제외했습니다.");
        }
        if (secretRule && hasDummyValue(sourceLine.isBlank() ? evidence : sourceLine) && !strongCredential) {
            return FalsePositiveDecision.keep(Severity.LOW, FalsePositiveRisk.HIGH, DetectionConfidence.LOW,
                    "dummy/example/placeholder 값으로 보여 실제 secret 가능성은 낮습니다. 문서나 예시값인지 확인하세요.");
        }
        if (strongCredential) {
            return FalsePositiveDecision.keep(match.severity(), FalsePositiveRisk.LOW, DetectionConfidence.HIGH,
                    knownCredentialPattern
                            ? "JWT/API key 형식의 강한 credential 패턴이 보여 오탐 가능성이 낮습니다."
                            : "secret 설정값이 충분히 길고 문자 분포 엔트로피가 높아 실제 credential 후보로 유지했습니다.");
        }
        if ("REACT_DANGEROUS_HTML".equals(match.ruleId())) {
            if (isHighFalsePositivePath(path) || isMinified(path)) {
                return FalsePositiveDecision.keep(match.severity(), FalsePositiveRisk.MEDIUM, DetectionConfidence.MEDIUM,
                        "테스트/샘플/생성 파일 또는 minified 파일의 dangerouslySetInnerHTML입니다. 사용자 입력 연결 여부를 검토하세요.");
            }
            return FalsePositiveDecision.keep(match.severity(), FalsePositiveRisk.LOW, DetectionConfidence.HIGH,
                    "HTML 렌더링 sink가 직접 발견되어 XSS 검토 우선순위를 유지합니다.");
        }
        if ("LOCAL_STORAGE_TOKEN".equals(match.ruleId())) {
            if (isHighFalsePositivePath(path) || isMinified(path)) {
                return FalsePositiveDecision.keep(Severity.MEDIUM, FalsePositiveRisk.MEDIUM, DetectionConfidence.MEDIUM,
                        "테스트/샘플/생성 파일의 localStorage 토큰 사용입니다. 실제 인증 흐름인지 검토하세요.");
            }
            return FalsePositiveDecision.keep(match.severity(), FalsePositiveRisk.LOW, DetectionConfidence.HIGH,
                    "localStorage와 token 키워드가 함께 사용되어 토큰 탈취 위험 검토가 필요합니다.");
        }
        if (isDocsPath(path)) {
            return FalsePositiveDecision.keep(Severity.LOW, FalsePositiveRisk.HIGH, DetectionConfidence.LOW,
                    "README/docs 문서의 예시 코드일 가능성이 높습니다. 실제 운영 설정으로 복사되는 값인지 검토하세요.");
        }
        if (isHighFalsePositivePath(path)) {
            Severity adjusted = executionContext ? match.severity() : downgrade(match.severity());
            FalsePositiveRisk risk = executionContext ? FalsePositiveRisk.MEDIUM : FalsePositiveRisk.HIGH;
            DetectionConfidence confidence = executionContext ? DetectionConfidence.MEDIUM : DetectionConfidence.LOW;
            String note = executionContext
                    ? "mock/test/sample/dataset 경로지만 실행/렌더링/리다이렉트 위험 문맥과 함께 발견되어 검토가 필요합니다."
                    : "mock/test/sample/dataset 경로에서 발견되어 오탐 가능성이 높습니다. 실제 배포 코드인지 확인하세요.";
            return FalsePositiveDecision.keep(adjusted, risk, confidence, note);
        }
        if (secretRule && isSuspiciousLongStaticData(combined) && !executionContext) {
            return FalsePositiveDecision.keep(Severity.LOW, FalsePositiveRisk.HIGH, DetectionConfidence.LOW,
                    "500자 이상의 긴 정적/base64성 데이터로 보입니다. 이미지, 모델, dataset, fixture 값이면 오탐 가능성이 높습니다.");
        }
        if (secretRule && isSuspiciousLongStaticData(combined)) {
            return FalsePositiveDecision.keep(match.severity(), FalsePositiveRisk.MEDIUM, DetectionConfidence.MEDIUM,
                    "긴 정적 문자열이지만 eval/HTML/atob/redirect 등 위험 문맥과 함께 사용되어 검토가 필요합니다.");
        }
        if (isMinified(path)) {
            return FalsePositiveDecision.keep(downgrade(match.severity()), FalsePositiveRisk.MEDIUM, DetectionConfidence.MEDIUM,
                    "minified JavaScript 파일에서 탐지되어 원본 소스 기준 재확인이 필요합니다.");
        }

        return FalsePositiveDecision.keep(match.severity(), FalsePositiveRisk.LOW, DetectionConfidence.HIGH,
                "오탐을 강하게 시사하는 경로, 값 패턴, 문맥이 발견되지 않았습니다.");
    }

    private String sourceLine(ProjectFile file, int line) {
        if (file == null || line <= 0 || line > file.lines().size()) {
            return "";
        }
        return file.lines().get(line - 1);
    }

    private boolean isLockFile(ProjectFile file, String path) {
        return (file != null && file.type() == ProjectFileType.LOCK_FILE)
                || path.endsWith("package-lock.json")
                || path.endsWith("yarn.lock")
                || path.endsWith("pnpm-lock.yaml");
    }

    private boolean looksLikeLockfileIntegrity(String value) {
        String lower = lower(value);
        return lower.contains("integrity") || lower.contains("resolved") || lower.contains("sha512-") || lower.contains("sha1-");
    }

    private boolean isGeneratedNoisePath(String path) {
        return path.contains("/node_modules/")
                || path.contains("/coverage/")
                || path.contains("/dist/")
                || path.contains("/build/")
                || path.startsWith("dist/")
                || path.startsWith("build/")
                || path.startsWith("coverage/")
                || path.startsWith("node_modules/");
    }

    private boolean isHighFalsePositivePath(String path) {
        return path.contains("/test/")
                || path.contains("/tests/")
                || path.contains("/__tests__/")
                || path.contains("/mock/")
                || path.contains("/mocks/")
                || path.contains("/fixture/")
                || path.contains("/fixtures/")
                || path.contains("/sample/")
                || path.contains("/samples/")
                || path.contains("/demo/")
                || path.contains("/dataset/")
                || path.contains("/datasets/")
                || path.contains("/generated/")
                || path.startsWith("test/")
                || path.startsWith("tests/")
                || path.startsWith("mock/")
                || path.startsWith("mocks/")
                || path.startsWith("fixture/")
                || path.startsWith("fixtures/")
                || path.startsWith("sample/")
                || path.startsWith("samples/")
                || path.startsWith("demo/")
                || path.startsWith("dataset/")
                || path.startsWith("datasets/")
                || path.startsWith("generated/");
    }

    private boolean isDocsPath(String path) {
        return path.endsWith("readme.md") || path.endsWith(".md") || path.contains("/docs/") || path.startsWith("docs/");
    }

    private boolean isMinified(String path) {
        return path.endsWith(".min.js");
    }

    private boolean isBase64DataUrl(String value) {
        return DATA_URL_PATTERN.matcher(value).find();
    }

    private boolean hasDummyValue(String value) {
        Matcher matcher = ASSIGNED_VALUE_PATTERN.matcher(value);
        String candidate = matcher.find() ? matcher.group(1) : value;
        return DUMMY_PATTERN.matcher(candidate).matches();
    }

    private boolean hasStrongCredentialPattern(String value) {
        return API_KEY_PATTERN.matcher(value).find() || JWT_PATTERN.matcher(value).find();
    }

    private boolean hasLongHighEntropyCredential(String sourceLine) {
        Matcher matcher = ASSIGNED_VALUE_PATTERN.matcher(sourceLine);
        if (!matcher.find()) {
            return false;
        }
        String value = matcher.group(1);
        if (value.length() < 64 || value.startsWith("http://") || value.startsWith("https://")) {
            return false;
        }
        return shannonEntropy(value) >= 3.5;
    }

    private double shannonEntropy(String value) {
        if (value.isEmpty()) {
            return 0;
        }
        Map<Integer, Integer> frequencies = new java.util.HashMap<>();
        value.chars().forEach(character -> frequencies.merge(character, 1, Integer::sum));
        double entropy = 0;
        for (int frequency : frequencies.values()) {
            double probability = frequency / (double) value.length();
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }
        return entropy;
    }

    private boolean hasExecutionContext(String value) {
        return EXECUTION_CONTEXT_PATTERN.matcher(value).find();
    }

    private boolean isSuspiciousLongStaticData(String value) {
        String longest = longestToken(value);
        if (longest.length() < 500) {
            return false;
        }
        double base64Ratio = base64CharacterRatio(longest);
        return base64Ratio >= 0.9 || STATIC_DATA_NAME_PATTERN.matcher(value).find();
    }

    private String longestToken(String value) {
        String longest = "";
        for (String token : value.split("[^A-Za-z0-9+/=_-]+")) {
            if (token.length() > longest.length()) {
                longest = token;
            }
        }
        return longest;
    }

    private double base64CharacterRatio(String value) {
        if (value.isBlank()) {
            return 0;
        }
        if (BASE64_CHARS.matcher(value).matches()) {
            return 1;
        }
        long count = value.chars()
                .filter(ch -> Character.isLetterOrDigit(ch) || ch == '+' || ch == '/' || ch == '=' || ch == '_' || ch == '-')
                .count();
        return count / (double) value.length();
    }

    private Severity downgrade(Severity severity) {
        return switch (severity) {
            case CRITICAL -> Severity.HIGH;
            case HIGH -> Severity.MEDIUM;
            case MEDIUM, LOW -> Severity.LOW;
        };
    }

    private String lower(String value) {
        return nullToEmpty(value).replace('\\', '/').toLowerCase(Locale.ROOT);
    }

    private String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private record FindingIdentity(String ruleId, String filePath, int line, String evidence) {
        private static FindingIdentity from(RuleMatch match) {
            return new FindingIdentity(match.ruleId(), match.filePath(), match.line(), match.evidence());
        }
    }
}
