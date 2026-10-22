package com.securedeploy.review;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.review.dto.*;
import com.securedeploy.project.coverage.CoverageLedger;
import com.securedeploy.analysis.typescript.ServerAnalysisSnapshot;
import com.securedeploy.risk.model.RiskAssessment;
import com.securedeploy.sca.model.ScaResult;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class ReviewResultSummaryTest {
    final ObjectMapper json=new ObjectMapper().findAndRegisterModules();
    SecurityReviewResponse base(){return new SecurityReviewResponse(null,null,"synthetic",1,0,100,"READY",List.of());}
    CoverageLedger coverage(String status){return new CoverageLedger(1,"coverage-v2",status,3,2,1,0,0,true,0,List.of(),
        List.of(new CoverageLedger.Analyzer("SUPABASE_RLS","PARTIAL","declarations",Map.of("SQL_NOT_RUN",1))),null);}
    SecurityReviewResponse policy(String state)throws Exception{
        var risk=json.readValue("{\"policyVersion\":\"risk-v1.2\",\"prioritizedDeploymentAssessment\":\""+state+"\",\"prioritySummary\":{\"BLOCKING\":"+(state.equals("BLOCKED")?1:0)+",\"REVIEW_REQUIRED\":0,\"SHOULD_FIX\":0}}",RiskAssessment.class);
        return new SecurityReviewResponse(null,null,"synthetic",1,0,100,"READY",List.of(),null,risk);
    }
    @Test void perfectScoreDoesNotHidePartialScopeOrStructuralCandidate()throws Exception{
        var server=json.readValue("{\"validatedFindings\":[{\"findingId\":\"flow:1\",\"sourceType\":\"TYPESCRIPT_DATA_FLOW\"}],\"authorizationContexts\":[{\"checks\":[]}]}",ServerAnalysisSnapshot.class);
        var response=policy("READY").withCoverage(coverage("PARTIAL")).withServerAnalysis(server);
        var summary=response.resultSummary();
        assertThat(summary.guidance()).isEqualTo("REVIEW_NEEDED");assertThat(summary.referenceScore()).isEqualTo(100);
        assertThat(summary.flowCandidates()).isEqualTo(1);assertThat(summary.coverageStatus()).isEqualTo("PARTIAL");
        assertThat(summary.authContextObserved()).isFalse();assertThat(summary.structuralComparison()).isEqualTo("NOT_COMPARED");
    }
    @Test void savedBlockingAssessmentAlwaysPrecedesScoreAndMissingEvidence()throws Exception{
        var response=policy("BLOCKED").withCoverage(coverage("FAILED"));var before=json.writeValueAsString(response.riskAssessment());
        assertThat(response.resultSummary().guidance()).isEqualTo("PRIORITY_ACTION_REQUIRED");
        assertThat(response.resultSummary().policyAssessment()).isEqualTo("BLOCKED");
        assertThat(json.writeValueAsString(response.riskAssessment())).isEqualTo(before);
    }
    @Test void emptyFindingsAndFailedOrDisabledLookupAreNotCleanResults()throws Exception{
        for(String state:List.of("UNAVAILABLE","DISABLED","PARTIAL")){
            var sca=json.readValue("{\"status\":\""+state+"\",\"summary\":{\"dependenciesAnalyzed\":0,\"unresolvedDependencies\":1}}",ScaResult.class);
            var summary=policy("READY").withCoverage(coverage("PARTIAL")).withSca(sca).resultSummary();
            assertThat(summary.guidance()).isEqualTo("SCOPE_REVIEW_NEEDED");assertThat(summary.scaStatus()).isEqualTo(state);
            assertThat(summary.unresolvedDependencies()).isEqualTo(1);
        }
        assertThat(policy("READY").withCoverage(coverage("FAILED")).resultSummary().guidance()).isEqualTo("ANALYSIS_INCOMPLETE");
    }
    @Test void historicalAbsenceRemainsUnknownRatherThanInventingZeros()throws Exception{
        var summary=base().resultSummary();
        assertThat(summary.flowCandidates()).isNull();assertThat(summary.declarationCandidates()).isNull();assertThat(summary.aiCandidates()).isNull();
        assertThat(summary.discoveredFiles()).isNull();assertThat(summary.scaStatus()).isEqualTo("NOT_RECORDED");
        assertThat(summary.guidance()).isEqualTo("SCOPE_REVIEW_NEEDED");
        var snapshot=json.readValue(json.writeValueAsBytes(summary),ReviewResultSummary.class);
        assertThat(snapshot).isEqualTo(summary);
    }
    @Test void summaryAddsNoSourceSecretOrPathAndKeepsPolicySnapshotRoundTrip()throws Exception{
        var response=policy("READY").withServerAnalysis(json.readValue("{\"files\":[{\"filePath\":\"private-path-example.ts\"}],\"limitations\":[\"SYNTHETIC_SECRET_NOT_FOR_UI\"]}",ServerAnalysisSnapshot.class));
        var encoded=json.writeValueAsString(response.resultSummary());
        assertThat(encoded).doesNotContain("private-path-example","SYNTHETIC_SECRET_NOT_FOR_UI");
        var risk=json.readValue(json.writeValueAsBytes(response.riskAssessment()),RiskAssessment.class);
        assertThat(risk).isEqualTo(response.riskAssessment());
    }
    @Test void observedSessionAndPolicyDeclarationsNeverProveRuntimeAuthorization()throws Exception{
        var server=json.readValue("{\"supabaseAnalysis\":{\"tables\":[{}],\"accesses\":[{\"authorizationEvidence\":{\"authChecks\":[{\"method\":\"getSession\"}]}}]}}",ServerAnalysisSnapshot.class);
        var summary=base().withServerAnalysis(server).resultSummary();
        assertThat(summary.authContextObserved()).isTrue();assertThat(summary.rlsDeclarationsObserved()).isTrue();
        assertThat(summary.runtimeVerification()).isEqualTo("NOT_PERFORMED");
    }
    @Test void ordinaryBranchesAndRegistrationAreNotAuthenticationEvidence()throws Exception{
        for(String kind:List.of("CONDITIONAL_CHECK","EXPRESS_REGISTRATION")){
            var server=json.readValue("{\"authorizationContexts\":[{\"checks\":[{\"kind\":\""+kind+"\"}]}]}",ServerAnalysisSnapshot.class);
            assertThat(base().withServerAnalysis(server).resultSummary().authContextObserved()).isFalse();
        }
        var login=json.readValue("{\"authorizationContexts\":[{\"checks\":[{\"kind\":\"LOGIN_CONTEXT_REFERENCE\"}]}]}",ServerAnalysisSnapshot.class);
        assertThat(base().withServerAnalysis(login).resultSummary().authContextObserved()).isTrue();
    }
}
