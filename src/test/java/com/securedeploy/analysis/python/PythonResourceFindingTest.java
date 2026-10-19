package com.securedeploy.analysis.python;

import com.securedeploy.analysis.typescript.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class PythonResourceFindingTest {
    @Test void groundedResourceFlowsConnectAndRoundTripWithoutChangingPriority() throws Exception {
        String code="import pickle\nfrom rest_framework.decorators import api_view\n@api_view(['POST'])\ndef endpoint(request):\n open(request.GET['file'])\n return pickle.loads(request.body)\n";
        var result=new PythonServerAnalyzer(new PythonAnalysisProperties()).analyze(PythonServerAnalyzerTest.project(code));
        assertThat(result.analyzerVersion()).isEqualTo("py-django-v7");
        assertThat(result.resourceUses()).hasSize(2);
        assertThat(result.validatedFindings()).hasSize(2).allMatch(f -> f.priority().name().equals("REVIEW_REQUIRED") && f.comparisonPolicy().equals("NOT_COMPARED"));
        assertThat(result.validatedFindings()).extracting(ServerFlowFinding::ruleId).containsExactly("PY_FILE_PATH_INPUT_FLOW","PY_UNSAFE_DESERIALIZATION_INPUT_FLOW");
        var converter=new ServerAnalysisConverter();String json=converter.convertToDatabaseColumn(result);
        assertThat(converter.convertToEntityAttribute(json)).isEqualTo(result);
        var node=(com.fasterxml.jackson.databind.node.ObjectNode)new com.fasterxml.jackson.databind.ObjectMapper().readTree(json);
        node.remove("resourceUses");node.putNull("validatedFindings");
        assertThat(converter.convertToEntityAttribute(node.toString()).resourceUses()).isNull();
    }
    @Test void sameHelperSinkGroupsDifferentInputEvidenceButNotDifferentOperations() {
        String code="from rest_framework.decorators import api_view\ndef read_file(path):\n return open(path)\n@api_view(['GET'])\ndef endpoint(request):\n read_file(request.GET['a'])\n read_file(request.GET['b'])\n";
        var result=new PythonServerAnalyzer(new PythonAnalysisProperties()).analyze(PythonServerAnalyzerTest.project(code));
        assertThat(result.validatedFindings()).hasSize(1);
        assertThat(result.validatedFindings().get(0).evidence()).hasSize(2);
        assertThat(result.validatedFindings().get(0).location().line()).isEqualTo(3);
    }
    @Test void unknownTransformsRemainCandidatesAndKnownDefensesRemainEvidence() {
        String code="from rest_framework.decorators import api_view\nfrom django.utils._os import safe_join\nimport yaml\n@api_view(['GET'])\ndef endpoint(request):\n open(check(request.GET['file']))\n open(safe_join('/fixed-base',request.GET['file']))\n yaml.load(request.body,Loader=yaml.SafeLoader)\n";
        var result=new PythonServerAnalyzer(new PythonAnalysisProperties()).analyze(PythonServerAnalyzerTest.project(code));
        assertThat(result.validatedFindings()).isEmpty();
        assertThat(result.findings()).hasSize(1).allMatch(f->f.confidence().equals("MEDIUM"));
        assertThat(result.resourceUses()).extracting(ServerAnalysisSnapshot.ResourceUse::kind).contains("UNRESOLVED_RESOURCE","LEXICALLY_CONFINED_PATH","SAFE_PARSER_DECLARATION");
        assertThat(new ServerAnalysisConverter().convertToDatabaseColumn(result)).doesNotContain("/fixed-base");
    }
}
