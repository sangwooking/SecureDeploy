package com.securedeploy.analysis.javaflow;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.project.model.ProjectFileType;
import com.securedeploy.project.model.ProjectStructure;
import com.securedeploy.review.dto.VulnerabilityResultResponse;
import com.securedeploy.review.service.SecurityReviewService;
import com.securedeploy.risk.model.RiskPriority;
import com.securedeploy.risk.policy.DefaultRiskPolicy;
import com.securedeploy.risk.policy.RiskReason;
import com.securedeploy.rule.filter.FalsePositiveAnalyzer;
import com.securedeploy.rule.rules.DangerousSqlRule;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

/** Frozen raw-pattern baseline, not assertions that these outcomes are correct.
 * Future integration tests must separately assert final structural decisions.
 * All source is synthetic text; it is never compiled or executed.
 */
class JavaSqlLegacyBaselineTest {
    private final DangerousSqlRule legacy = new DangerousSqlRule();

    private ProjectFile source(String body) {
        String text = "class QueryEndpoint {\nvoid lookup(String input) {\n" + body + "\n}\n}";
        return new ProjectFile(Path.of("QueryEndpoint.java"), "QueryEndpoint.java",
                ProjectFileType.JAVA, text.lines().toList());
    }

    @Test void rawPatternWarnsOnConstantOverwriteAndFixedStatementCreation() {
        var overwritten = source("String value=input;\nif (7*42-86>200) value=\"fixed\";\n"
                + "String sql=\"SELECT id FROM items WHERE name='\"+value+\"'\";\nconnection.prepareStatement(sql).execute();");
        var fixed = source("java.sql.Statement statement=connection.createStatement();\nstatement.execute(\"SELECT 1\");");
        assertThat(legacy.evaluate(overwritten)).hasSize(1);
        assertThat(legacy.evaluate(fixed)).hasSize(1);
    }

    @Test void rawPatternMissesSplitConstructionAndCallableSql() {
        var split = source("String sql=\"SELECT id FROM items WHERE name=\";\nsql += input;\nconnection.prepareStatement(sql).execute();");
        var callable = source("String sql=\"{call \"+input+\"}\";\njava.sql.CallableStatement statement=connection.prepareCall(sql);\nstatement.execute();");
        assertThat(legacy.evaluate(split)).isEmpty();
        assertThat(legacy.evaluate(callable)).isEmpty();
    }

    @Test void rawPatternFindsDirectConcatenationIncludingBeforeBinding() {
        var direct = source("String sql=\"SELECT id FROM items WHERE name=\"+input;\nconnection.prepareStatement(sql).execute();");
        var boundTooLate = source("java.sql.PreparedStatement s=connection.prepareStatement(\"SELECT id FROM items WHERE name=\"+input);\ns.setString(1,input);\ns.execute();");
        assertThat(legacy.evaluate(direct)).hasSize(1);
        assertThat(legacy.evaluate(boundTooLate)).hasSize(1);
    }

    @Test void ordinaryValueBindingHasNoRawPatternWarning() {
        var bound = source("java.sql.PreparedStatement s=connection.prepareStatement(\"SELECT id FROM items WHERE name=?\");\ns.setString(1,input);\ns.execute();");
        assertThat(legacy.evaluate(bound)).isEmpty();
    }

    @Test void falsePositiveProcessingDoesNotResolveSqlAndItsScorePenaltyIsReal() {
        var fixed = source("java.sql.Statement statement=connection.createStatement();\nstatement.execute(\"SELECT 1\");");
        var project = new ProjectStructure(Path.of("."), List.of(fixed));
        var matches = new FalsePositiveAnalyzer().analyze(project, legacy.evaluate(fixed));
        assertThat(matches).hasSize(1);
        var response = new SecurityReviewService().createResponse("synthetic", 1, matches);
        assertThat(response.securityScore()).isEqualTo(86);
        var decision = new DefaultRiskPolicy().code(VulnerabilityResultResponse.from(matches.get(0)));
        assertThat(decision.priority()).isEqualTo(RiskPriority.REVIEW_REQUIRED);
        assertThat(decision.reason()).isEqualTo(RiskReason.PATTERN_REQUIRES_CONTEXT);
    }
}
