package com.securedeploy.analysis.python;
import com.securedeploy.analysis.typescript.*;
import com.securedeploy.project.model.*;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class ServiceSecurityFindingTest {
    @Test void springStacktraceRuleStillRequiresExplicitAlwaysAndRecommendsNonPublicDiagnostics() {
        var rule=new com.securedeploy.rule.rules.StacktraceExposureRule();
        var f=new ProjectFile(Path.of("application.properties"),"application.properties",ProjectFileType.PROPERTIES,List.of("server.error.include-stacktrace=always"));
        assertThat(rule.evaluate(f)).hasSize(1);assertThat(rule.evaluate(f).get(0).recommendation()).contains("never").doesNotContain("on_param");
        assertThat(rule.evaluate(new ProjectFile(f.absolutePath(),f.relativePath(),f.type(),List.of("server.error.include-stacktrace=never")))).isEmpty();
    }
    static final String SOURCE="""
            import traceback
            import requests
            from django.http import JsonResponse
            from rest_framework.decorators import api_view
            @api_view(['GET'])
            def endpoint(request):
                requests.get('https://fixture.invalid',timeout=None)
                return JsonResponse({'error':traceback.format_stack()})
            """;
    @Test void serviceAndErrorEvidenceConnectWithoutSensitiveDataOrLegacyInference() throws Exception {
        var r=new PythonServerAnalyzer(new PythonAnalysisProperties()).analyze(PythonServerAnalyzerTest.project(SOURCE));
        assertThat(r.validatedFindings()).hasSize(2).allSatisfy(f->{assertThat(f.priority().name()).isEqualTo("REVIEW_REQUIRED");assertThat(f.comparisonPolicy()).isEqualTo("NOT_COMPARED");});
        assertThat(r.findings()).extracting(ServerAnalysisSnapshot.Finding::kind).contains("CWE-209","CWE-400");
        assertThat(r.serviceUses().get(0).status()).isEqualTo("EXPLICIT_TIMEOUT_DISABLED");
        assertThat(r.withTokenUses(r.tokenUses()).withExposureUses(r.exposureUses()).withSelectionCoverage(r.selectionCoverage()).serviceUses()).isEqualTo(r.serviceUses());
        var converter=new ServerAnalysisConverter();String json=converter.convertToDatabaseColumn(r);
        assertThat(converter.convertToEntityAttribute(json)).isEqualTo(r);assertThat(json).doesNotContain("https://fixture.invalid");
        var tree=new com.fasterxml.jackson.databind.ObjectMapper().readTree(json);((com.fasterxml.jackson.databind.node.ObjectNode)tree).remove("serviceUses");
        assertThat(converter.convertToEntityAttribute(tree.toString()).serviceUses()).isNull();
    }
    @Test void typescriptKnownStackIsErrorNotADuplicateSensitiveExposure() {
        String code="export default {fetch(request){try{throw new Error('fixture-internal-text')}catch(e){return Response.json({error:e.stack});}}}";
        var project=new ProjectStructure(Path.of("/unreadable-target"),List.of(new ProjectFile(Path.of("/unreadable-target/worker.ts"),"worker.ts",ProjectFileType.TYPESCRIPT,code.lines().toList())));
        var r=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties()).analyze(project);
        assertThat(r.validatedFindings()).hasSize(1);assertThat(r.validatedFindings().get(0).ruleId()).isEqualTo("TS_ERROR_DETAIL_EXPOSURE");
        assertThat(new ServerAnalysisConverter().convertToDatabaseColumn(r)).doesNotContain("fixture-internal-text");
    }
}
