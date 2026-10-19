package com.securedeploy.analysis.python;

import com.securedeploy.analysis.typescript.ServerAnalysisConverter;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class PythonTokenFindingTest {
    static final String SOURCE = """
            import jwt
            from rest_framework.decorators import api_view
            from rest_framework.exceptions import PermissionDenied
            @api_view(['GET'])
            def endpoint(request):
                claims=jwt.decode(request.headers['Authorization'],options={'verify_signature':False})
                if claims['role'] != 'admin':
                    raise PermissionDenied()
                return 'ok'
            """;
    @Test void verifiedTokenEvidenceConnectsToSupplementalFindingAndSurvivesSnapshotCopies() {
        var result=new PythonServerAnalyzer(new PythonAnalysisProperties()).analyze(PythonServerAnalyzerTest.project(SOURCE));
        assertThat(result.status()).isNotEqualTo("UNAVAILABLE");
        assertThat(result.tokenUses()).hasSize(1);
        assertThat(result.validatedFindings()).hasSize(1);
        var finding=result.validatedFindings().get(0);
        assertThat(finding.ruleId()).isEqualTo("PY_JWT_UNVERIFIED_ACCESS_DECISION");
        assertThat(finding.priority().name()).isEqualTo("REVIEW_REQUIRED");
        assertThat(finding.comparisonPolicy()).isEqualTo("NOT_COMPARED");
        var converter=new ServerAnalysisConverter();
        assertThat(converter.convertToEntityAttribute(converter.convertToDatabaseColumn(result))).isEqualTo(result);
        assertThat(result.withSelectionCoverage(result.selectionCoverage()).withResourceUses(result.resourceUses()).withDeploymentAnalysis(result.deploymentAnalysis()).tokenUses()).isEqualTo(result.tokenUses());
        var display=new PythonServerAnalyzer(new PythonAnalysisProperties()).analyze(PythonServerAnalyzerTest.project(SOURCE.replace("    if claims['role'] != 'admin':\n        raise PermissionDenied()\n", "")));
        assertThat(display.validatedFindings()).isEmpty();
    }
    @Test void signingSecretsNeverEnterSnapshotsAndLegacyEvidenceStaysNull() throws Exception {
        var marker="synthetic-signing-material-not-a-real-key";
        var source=SOURCE.substring(0,SOURCE.indexOf("    claims="))+"    return jwt.encode({},'"+marker+"',algorithm='HS256')\n";
        var result=new PythonServerAnalyzer(new PythonAnalysisProperties()).analyze(PythonServerAnalyzerTest.project(source));
        assertThat(result.validatedFindings()).hasSize(1);
        assertThat(result.tokenUses().get(0).keySource()).isEqualTo("FIXED_LITERAL");
        var converter=new ServerAnalysisConverter();var json=converter.convertToDatabaseColumn(result);
        assertThat(json).doesNotContain(marker);
        var tree=new com.fasterxml.jackson.databind.ObjectMapper().readTree(json);
        ((com.fasterxml.jackson.databind.node.ObjectNode)tree).remove("tokenUses");
        assertThat(converter.convertToEntityAttribute(tree.toString()).tokenUses()).isNull();
    }
}
