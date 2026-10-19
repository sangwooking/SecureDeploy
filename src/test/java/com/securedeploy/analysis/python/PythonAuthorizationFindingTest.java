package com.securedeploy.analysis.python;

import com.securedeploy.analysis.typescript.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class PythonAuthorizationFindingTest {
    static final String UNSAFE = """
            from django.db import models
            from django.conf import settings
            from rest_framework.decorators import api_view, permission_classes
            from rest_framework.permissions import IsAuthenticated
            from rest_framework.exceptions import PermissionDenied
            class Record(models.Model):
                holder = models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.CASCADE)
            @api_view(['POST'])
            @permission_classes([IsAuthenticated])
            def endpoint(request):
                obj=Record.objects.get(pk=request.GET['key'])
                if obj.holder_id == request.user.id:
                    raise PermissionDenied()
                obj.delete()
            """;
    static final String SAFE = UNSAFE.replace("holder_id ==", "holder_id !=");
    @Test void groundedCandidateConnectsButCorrectGuardAndMissingGuardDoNotBecomeFindings() throws Exception {
        var analyzer=new PythonServerAnalyzer(new PythonAnalysisProperties());
        var result=analyzer.analyze(PythonServerAnalyzerTest.project(UNSAFE));
        assertThat(result.analyzerVersion()).isEqualTo("py-django-v6");
        assertThat(result.validatedFindings()).hasSize(1);
        var finding=result.validatedFindings().get(0);
        assertThat(finding.ruleId()).isEqualTo("PY_AUTHORIZATION_INVERTED_OWNER_GUARD");
        assertThat(finding.priority().name()).isEqualTo("REVIEW_REQUIRED");
        assertThat(finding.comparisonPolicy()).isEqualTo("NOT_COMPARED");
        assertThat(result.authorizationContexts().get(0).details().authenticationStatus()).isEqualTo("DECLARED_LOGIN_REQUIRED");
        var converter=new ServerAnalysisConverter();String json=converter.convertToDatabaseColumn(result);
        assertThat(converter.convertToEntityAttribute(json)).isEqualTo(result);
        assertThat(json).doesNotContain("models.ForeignKey", "on_delete=", "request.GET[");
        var safe=analyzer.analyze(PythonServerAnalyzerTest.project(SAFE));
        assertThat(safe.validatedFindings()).isEmpty();
        assertThat(safe.authorizationContexts().get(0).details().accesses()).anyMatch(a->a.conclusion().equals("OWNER_GUARD_EVIDENCE"));
        var absent=analyzer.analyze(PythonServerAnalyzerTest.project(UNSAFE.replace("    if obj.holder_id == request.user.id:\n        raise PermissionDenied()\n", "")));
        assertThat(absent.validatedFindings()).isEmpty();
    }
    @Test void legacyDetailsRemainNullRatherThanInferred() throws Exception {
        var result=new PythonServerAnalyzer(new PythonAnalysisProperties()).analyze(PythonServerAnalyzerTest.project(SAFE));
        var mapper=new com.fasterxml.jackson.databind.ObjectMapper();var json=mapper.valueToTree(result);
        ((com.fasterxml.jackson.databind.node.ObjectNode)json.path("authorizationContexts").get(0)).remove("details");
        assertThat(new ServerAnalysisConverter().convertToEntityAttribute(json.toString()).authorizationContexts().get(0).details()).isNull();
    }
}
