package com.securedeploy.ai.service;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.ai.config.AiProperties;
import com.securedeploy.editing.WorkspacePatch;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;
class OpenAiDependencyAdviceTransportTest {
    @Test void sharesBoundedStructuredResponsesTransportWithoutToolsOrStorage()throws Exception{
        var json=new ObjectMapper();var props=new AiProperties();props.getOpenai().setApiKey("synthetic-only");var builder=RestClient.builder().baseUrl("https://api.openai.com/v1");var server=MockRestServiceServer.bindTo(builder).build();
        var output=Map.ofEntries(Map.entry("evidenceHash","hash"),Map.entry("packageName","undici"),Map.entry("lockedVersion","7.29.1"),Map.entry("advisoryId","GHSA-test"),Map.entry("decision","NEEDS_REVIEW"),Map.entry("candidateVersion",""),Map.entry("explanation","문맥이 부족합니다."),Map.entry("whyItMatters","추가 확인이 필요합니다."),Map.entry("possibleImpact","실제 영향은 미확인입니다."),Map.entry("recommendedAction","직접 검토하세요."),Map.entry("verificationSteps",List.of("기능을 확인하세요.")),Map.entry("uncertainties",List.of("호환성 미확인")));
        server.expect(requestTo("https://api.openai.com/v1/responses")).andExpect(r->{var d=json.readTree(((org.springframework.mock.http.client.MockClientHttpRequest)r).getBodyAsBytes());assertEquals("dependency_update_advice_v1",d.at("/text/format/name").asText());assertEquals(2000,d.path("max_output_tokens").asInt());assertFalse(d.path("store").asBoolean());assertFalse(d.has("tools"));assertTrue(d.at("/text/format/strict").asBoolean());}).andRespond(withSuccess(json.writeValueAsString(Map.of("status","completed","output_text",json.writeValueAsString(output))),MediaType.APPLICATION_JSON));
        var provider=MockMeteredTransport.provider(props,json,builder.build());assertEquals("NEEDS_REVIEW",provider.generateDependencyAdvice(new WorkspacePatch.Prompt("trusted","data",Map.of())).decision());server.verify();
    }
}
