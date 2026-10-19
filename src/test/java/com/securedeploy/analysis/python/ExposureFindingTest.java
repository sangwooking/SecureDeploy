package com.securedeploy.analysis.python;

import com.securedeploy.analysis.typescript.*;
import com.securedeploy.project.model.*;
import com.securedeploy.ai.context.SnippetCollector;
import com.securedeploy.ai.remediation.RemediationSanitizer;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class ExposureFindingTest {
    static final String PYTHON = """
            from rest_framework.decorators import api_view
            from rest_framework.response import Response
            from django.conf import settings
            @api_view(['GET'])
            def endpoint(request):
                return Response({'value':settings.SECRET_KEY})
            """;
    @Test void pythonEvidenceConnectsAndPreservesLegacyNullAndSnapshotCopies() throws Exception {
        var result=new PythonServerAnalyzer(new PythonAnalysisProperties()).analyze(PythonServerAnalyzerTest.project(PYTHON));
        assertThat(result.exposureUses()).hasSize(1);assertThat(result.validatedFindings()).hasSize(1);
        assertThat(result.validatedFindings().get(0).priority().name()).isEqualTo("REVIEW_REQUIRED");
        assertThat(result.validatedFindings().get(0).comparisonPolicy()).isEqualTo("NOT_COMPARED");
        var converter=new ServerAnalysisConverter();String json=converter.convertToDatabaseColumn(result);
        assertThat(converter.convertToEntityAttribute(json)).isEqualTo(result);
        assertThat(result.withTokenUses(result.tokenUses()).withResourceUses(result.resourceUses()).withSelectionCoverage(result.selectionCoverage()).exposureUses()).isEqualTo(result.exposureUses());
        var tree=new com.fasterxml.jackson.databind.ObjectMapper().readTree(json);((com.fasterxml.jackson.databind.node.ObjectNode)tree).remove("exposureUses");
        assertThat(converter.convertToEntityAttribute(tree.toString()).exposureUses()).isNull();
    }
    @Test void typescriptFindingContainsNoCredentialAndAuditInputUsesExistingSharedMasking() {
        String fake="ghp_"+"a".repeat(36);
        String source="export default {fetch(request,env){const key='"+fake+"';return Response.json({key});}}";
        var project=new ProjectStructure(Path.of("/unreadable-target"),List.of(new ProjectFile(Path.of("/unreadable-target/functions/api/demo.ts"),"functions/api/demo.ts",ProjectFileType.TYPESCRIPT,source.lines().toList())));
        var result=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties()).analyze(project);
        assertThat(result.exposureUses()).hasSize(1);assertThat(result.validatedFindings()).hasSize(1);
        assertThat(result.validatedFindings().get(0).ruleId()).isEqualTo("TS_SENSITIVE_DATA_EXPOSURE");
        assertThat(new ServerAnalysisConverter().convertToDatabaseColumn(result)).doesNotContain(fake);
        String audit=new SnippetCollector(new RemediationSanitizer()).collect(project).toString();
        assertThat(audit).doesNotContain(fake).contains("redacted");
    }
}
