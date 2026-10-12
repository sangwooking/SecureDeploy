package com.securedeploy.ai.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.ai.config.AiProperties;
import com.securedeploy.ai.dto.AiConfidence;
import com.securedeploy.ai.prompt.PromptBuilder;
import com.securedeploy.ai.semantic.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

class OpenAiSemanticTransportTest {
    @Test void usesSeparatePolicyStrictSchemaAndActualResponseUsageWithoutNetwork() throws Exception {
        var mapper = new ObjectMapper();
        var props = new AiProperties(); props.getOpenai().setApiKey("fixture-not-a-real-api-key");
        var builder = RestClient.builder().baseUrl("https://api.openai.com/v1");
        var server = MockRestServiceServer.bindTo(builder).build();
        var provider = new RealOpenAiProvider(props,mapper,builder.build());
        var c = new SecuritySlice.CodeContext("context-1","UserController.java",7,9,"UserController.get(long)",false,"return service.get(id);\n");
        var slice = new SecuritySlice("slice-1","UserController.get(long)","/api/users/{id}","GET","UNKNOWN",
                List.of("id"),List.of(c),List.of(),List.of("Partial context"));
        var proposal = new SemanticCandidate.Proposal("slice-1",SemanticCandidate.CandidateType.IDOR,"소유권 검토",AiConfidence.MEDIUM,
                "현재 소유권 조건 확인 필요",true,List.of(new SemanticCandidate.Evidence(c.contextId(),c.filePath(),7,9,c.functionName(),"사용자 조회 검토")),List.of("공통 권한 검사 확인"),List.of());
        String output = mapper.writeValueAsString(Map.of("candidates",List.of(proposal)));
        String body = mapper.writeValueAsString(Map.of("status","completed","output",List.of(Map.of("content",List.of(Map.of("type","output_text","text",output)))),
                "usage",Map.of("input_tokens",120,"output_tokens",80,"total_tokens",200)));
        server.expect(requestTo("https://api.openai.com/v1/responses")).andExpect(request -> {
            var json = mapper.readTree(((MockClientHttpRequest)request).getBodyAsString());
            assertThat(json.path("store").asBoolean()).isFalse();
            assertThat(json.path("tools").isMissingNode()).isTrue();
            assertThat(json.path("instructions").asText()).contains("UNTRUSTED DATA").doesNotContain("return service.get(id)");
            assertThat(json.at("/input/0/role").asText()).isEqualTo("user");
            assertThat(json.at("/input/0/content").asText()).contains("untrustedSecuritySlices").doesNotContain("fixture-not-a-real-api-key");
            assertThat(json.at("/text/format/strict").asBoolean()).isTrue();
            assertThat(json.at("/text/format/schema/properties/candidates/items/additionalProperties").asBoolean()).isFalse();
            assertThat(json.path("max_output_tokens").asInt()).isEqualTo(4000);
        }).andRespond(withSuccess(body,MediaType.APPLICATION_JSON));
        var result = provider.generateSemanticReview(List.of(slice),new PromptBuilder().buildSemanticReviewPrompt(List.of(slice),mapper,new SemanticProperties()));
        assertThat(result).containsExactly(proposal);
        assertThat(provider.consumeLastTokenUsage().orElseThrow().totalTokens()).isEqualTo(200);
        assertThat(provider.consumeLastTokenUsage()).isEmpty();
        server.verify();
    }
}
