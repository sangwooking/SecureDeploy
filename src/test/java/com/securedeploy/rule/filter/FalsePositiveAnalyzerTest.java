package com.securedeploy.rule.filter;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.project.model.ProjectFileType;
import com.securedeploy.project.model.ProjectStructure;
import com.securedeploy.review.dto.SecurityReviewResponse;
import com.securedeploy.review.service.SecurityReviewService;
import com.securedeploy.rule.rules.HardcodedPasswordRule;
import com.securedeploy.rule.rules.HardcodedSecretRule;
import com.securedeploy.rule.model.DetectionConfidence;
import com.securedeploy.rule.model.FalsePositiveRisk;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.RuleMatch;
import com.securedeploy.rule.model.Severity;
import java.nio.file.Path;
import java.util.List;
import java.util.Random;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

class FalsePositiveAnalyzerTest {

    private final FalsePositiveAnalyzer analyzer = new FalsePositiveAnalyzer();

    @Test
    void excludesBase64ImageDataUrlFromSecretFindings() {
        String line = "export const imageData = 'data:image/png;base64," + "A".repeat(700) + "';";
        RuleMatch match = frontendSecret("src/assets/imageData.ts", line, Severity.HIGH);

        List<RuleMatch> analyzed = analyze(ProjectFileType.TYPESCRIPT, "src/assets/imageData.ts", line, match);

        assertThat(analyzed).isEmpty();
    }

    @Test
    void lowersLongStaticMockDataConfidenceInsteadOfDroppingIt() {
        String line = "export const mockDatasetToken = '" + "A".repeat(650) + "';";
        RuleMatch match = frontendSecret("src/mocks/mockData.ts", line, Severity.HIGH);

        List<RuleMatch> analyzed = analyze(ProjectFileType.TYPESCRIPT, "src/mocks/mockData.ts", line, match);

        assertThat(analyzed).hasSize(1);
        RuleMatch adjusted = analyzed.get(0);
        assertThat(adjusted.severity()).isEqualTo(Severity.MEDIUM);
        assertThat(adjusted.falsePositiveRisk()).isEqualTo(FalsePositiveRisk.HIGH);
        assertThat(adjusted.confidence()).isEqualTo(DetectionConfidence.LOW);
        assertThat(adjusted.analysisNote()).contains("오탐 가능성이 높습니다");
    }

    @Test
    void keepsJwtCredentialAsHighConfidence() {
        String line = "const accessToken = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signaturevalue';";
        RuleMatch match = frontendSecret("src/auth/session.ts", line, Severity.HIGH);

        List<RuleMatch> analyzed = analyze(ProjectFileType.TYPESCRIPT, "src/auth/session.ts", line, match);

        assertThat(analyzed).hasSize(1);
        assertThat(analyzed.get(0).severity()).isEqualTo(Severity.HIGH);
        assertThat(analyzed.get(0).falsePositiveRisk()).isEqualTo(FalsePositiveRisk.LOW);
        assertThat(analyzed.get(0).confidence()).isEqualTo(DetectionConfidence.HIGH);
    }

    @Test
    void keepsApiKeyPatternAsHighConfidence() {
        String line = "const apiKey = 'sk-abcdefghijklmnopqrstuvwxyz123456';";
        RuleMatch match = frontendSecret("src/api/client.ts", line, Severity.HIGH);

        List<RuleMatch> analyzed = analyze(ProjectFileType.TYPESCRIPT, "src/api/client.ts", line, match);

        assertThat(analyzed).hasSize(1);
        assertThat(analyzed.get(0).severity()).isEqualTo(Severity.HIGH);
        assertThat(analyzed.get(0).confidence()).isEqualTo(DetectionConfidence.HIGH);
    }

    @Test
    void excludesPackageLockIntegrityHashFromSecretFindings() {
        String line = "\"integrity\": \"sha512-" + "A".repeat(140) + "\"";
        RuleMatch match = frontendSecret("package-lock.json", line, Severity.HIGH);

        List<RuleMatch> analyzed = analyze(ProjectFileType.LOCK_FILE, "package-lock.json", line, match);

        assertThat(analyzed).isEmpty();
    }

    @Test
    void keepsLongStringWhenUsedInEvalContext() {
        String line = "eval('" + "A".repeat(650) + "');";
        RuleMatch match = frontendSecret("src/generated/payload.ts", line, Severity.HIGH);

        List<RuleMatch> analyzed = analyze(ProjectFileType.TYPESCRIPT, "src/generated/payload.ts", line, match);

        assertThat(analyzed).hasSize(1);
        assertThat(analyzed.get(0).severity()).isEqualTo(Severity.HIGH);
        assertThat(analyzed.get(0).confidence()).isEqualTo(DetectionConfidence.MEDIUM);
        assertThat(analyzed.get(0).analysisNote()).contains("위험 문맥");
    }

    @Test
    void keepsDangerouslySetInnerHtmlAsXssSignal() {
        String line = "<div dangerouslySetInnerHTML={{ __html: longHtml }} />";
        RuleMatch match = new RuleMatch(
                "REACT_DANGEROUS_HTML",
                RuleCategory.CLIENT_XSS,
                Severity.HIGH,
                "src/pages/NoticePage.tsx",
                1,
                "dangerouslySetInnerHTML 사용",
                "sanitize 하세요.",
                line
        );

        List<RuleMatch> analyzed = analyze(ProjectFileType.REACT, "src/pages/NoticePage.tsx", line, match);

        assertThat(analyzed).hasSize(1);
        assertThat(analyzed.get(0).severity()).isEqualTo(Severity.HIGH);
        assertThat(analyzed.get(0).confidence()).isEqualTo(DetectionConfidence.HIGH);
    }

    @Test
    void downgradesPlaceholderValuesReportedByActualSecretRules() {
        ProjectFile file = propertiesFile(List.of(
                "password = \"password\"",
                "db.password=changeme",
                "secret=YOUR_SECRET_HERE",
                "api.key=YOUR_API_KEY"
        ));

        List<RuleMatch> analyzed = analyzeActualSecretRules(file);

        assertThat(analyzed).hasSize(4).allSatisfy(match -> {
            assertThat(match.severity()).isEqualTo(Severity.LOW);
            assertThat(match.falsePositiveRisk()).isEqualTo(FalsePositiveRisk.HIGH);
            assertThat(match.confidence()).isEqualTo(DetectionConfidence.LOW);
            assertThat(match.analysisNote()).contains("placeholder");
            assertThat(match.evidence()).doesNotContain("changeme", "YOUR_SECRET_HERE", "YOUR_API_KEY");
        });
    }

    @Test
    void keepsJwtApiKeyAndLongRandomSecretAsHighConfidence() {
        String longRandom = randomFakeSecret(320);
        ProjectFile file = propertiesFile(List.of(
                "jwt.secret=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signaturevalue",
                "api.key=sk-abcdefghijklmnopqrstuvwxyz123456",
                "service.secret=" + longRandom
        ));

        List<RuleMatch> analyzed = analyzeActualSecretRules(file);

        assertThat(analyzed).hasSize(3).allSatisfy(match -> {
            assertThat(match.falsePositiveRisk()).isEqualTo(FalsePositiveRisk.LOW);
            assertThat(match.confidence()).isEqualTo(DetectionConfidence.HIGH);
        });
        assertThat(analyzed).extracting(RuleMatch::evidence)
                .allSatisfy(evidence -> assertThat(evidence).doesNotContain(longRandom));
        assertThat(analyzed.get(2).analysisNote()).contains("엔트로피");
    }

    @Test
    void doesNotTreatNormalWordsContainingTestAsPlaceholders() {
        ProjectFile file = propertiesFile(List.of("service.secret=latest"));

        List<RuleMatch> analyzed = analyzeActualSecretRules(file);

        assertThat(analyzed).hasSize(1);
        assertThat(analyzed.get(0).falsePositiveRisk()).isEqualTo(FalsePositiveRisk.LOW);
        assertThat(analyzed.get(0).confidence()).isEqualTo(DetectionConfidence.HIGH);
        assertThat(analyzed.get(0).analysisNote()).contains("오탐을 강하게 시사하는");
    }

    @Test
    void leavesNormalLongStringsOutOfSecretRuleFindings() {
        String longUrl = "https://service.invalid/path/" + "segment".repeat(90);
        String description = "Ordinary documentation text, not a credential. ".repeat(30);
        String longFixture = "ordinary fixture content ".repeat(40);
        String longBuild = "webpack dependency metadata ".repeat(40);
        ProjectFile file = new ProjectFile(
                Path.of("src/main.ts"),
                "src/main.ts",
                ProjectFileType.TYPESCRIPT,
                List.of(
                        "const endpoint = \"" + longUrl + "\";",
                        "const requestId = \"550e8400-e29b-41d4-a716-446655440000\";",
                        "const checksum = \"" + "a".repeat(64) + "\";",
                        "const description = \"" + description + "\";",
                        "const testData = \"" + longFixture + "\";",
                        "const buildInfo = \"" + longBuild + "\";"
                )
        );

        List<RuleMatch> raw = Stream.of(new HardcodedSecretRule(), new HardcodedPasswordRule())
                .flatMap(rule -> rule.evaluate(file).stream())
                .toList();

        assertThat(raw).isEmpty();
        assertThat(analyzer.analyze(new ProjectStructure(Path.of("."), List.of(file)), raw)).isEmpty();
    }

    @Test
    void deduplicatesOnlyIdenticalFindingsAtTheSameLocation() {
        String line = "secret=YOUR_SECRET_HERE";
        RuleMatch match = frontendSecret("src/auth/config.ts", line, Severity.HIGH);
        ProjectFile file = new ProjectFile(Path.of("src/auth/config.ts"), "src/auth/config.ts", ProjectFileType.TYPESCRIPT, List.of(line));

        List<RuleMatch> analyzed = analyzer.analyze(
                new ProjectStructure(Path.of("."), List.of(file)),
                List.of(match, match)
        );

        assertThat(analyzed).hasSize(1);
    }

    @Test
    void serializesFalsePositiveMetadataInReviewResponseJson() throws Exception {
        ProjectFile file = propertiesFile(List.of("password=changeme"));
        RuleMatch match = analyzeActualSecretRules(file).get(0);
        SecurityReviewResponse response = new SecurityReviewService().createResponse(
                "fixture-project", 1, List.of(match)
        );

        JsonNode json = new ObjectMapper().readTree(new ObjectMapper().writeValueAsBytes(response));
        JsonNode finding = json.path("vulnerabilities").get(0);

        assertThat(finding.path("falsePositiveRisk").asText()).isEqualTo("HIGH");
        assertThat(finding.path("confidence").asText()).isEqualTo("LOW");
        assertThat(finding.path("analysisNote").asText()).contains("placeholder");
        assertThat(finding.path("evidence").asText()).doesNotContain("changeme");
    }

    private List<RuleMatch> analyzeActualSecretRules(ProjectFile file) {
        List<RuleMatch> raw = Stream.of(new HardcodedPasswordRule(), new HardcodedSecretRule())
                .flatMap(rule -> rule.evaluate(file).stream())
                .toList();
        return analyzer.analyze(new ProjectStructure(Path.of("."), List.of(file)), raw);
    }

    private ProjectFile propertiesFile(List<String> lines) {
        return new ProjectFile(Path.of("application.properties"), "application.properties", ProjectFileType.PROPERTIES, lines);
    }

    private String randomFakeSecret(int length) {
        String alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";
        Random random = new Random(20261006);
        StringBuilder value = new StringBuilder(length);
        for (int index = 0; index < length; index++) {
            value.append(alphabet.charAt(random.nextInt(alphabet.length())));
        }
        return value.toString();
    }

    private RuleMatch frontendSecret(String path, String line, Severity severity) {
        return new RuleMatch(
                "HARDCODED_FRONTEND_SECRET",
                RuleCategory.CLIENT_SECRET_EXPOSURE,
                severity,
                path,
                1,
                "프론트엔드 secret 후보",
                "secret을 분리하세요.",
                line
        );
    }

    private List<RuleMatch> analyze(ProjectFileType type, String path, String line, RuleMatch match) {
        ProjectFile file = new ProjectFile(Path.of(path), path, type, List.of(line));
        return analyzer.analyze(new ProjectStructure(Path.of("."), List.of(file)), List.of(match));
    }
}
