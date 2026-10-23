package com.securedeploy.ai.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.ai.config.AiProperties;
import com.securedeploy.editing.WorkspacePatch;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

class OpenAiPatchTransportTest {
    final ObjectMapper mapper=new ObjectMapper();
    @Test void usesExistingResponsesProviderWithNoToolsNoStorageAndStrictSchema()throws Exception{
        var props=new AiProperties();props.getOpenai().setApiKey("synthetic-only");var builder=RestClient.builder().baseUrl("https://api.openai.com/v1");
        var server=MockRestServiceServer.bindTo(builder).build();var provider=new RealOpenAiProvider(props,mapper,builder.build());
        var output=new WorkspacePatch.Output("PATCH","file",1,"hash","debug=false","설정 검토",List.of("로컬 테스트"),List.of("운영 미확인"));
        server.expect(requestTo("https://api.openai.com/v1/responses")).andExpect(request->{var data=mapper.readTree(((org.springframework.mock.http.client.MockClientHttpRequest)request).getBodyAsBytes());
            assertFalse(data.path("store").asBoolean());assertEquals(2000,data.path("max_output_tokens").asInt());assertFalse(data.has("tools"));assertTrue(data.at("/text/format/strict").asBoolean());
        }).andRespond(withSuccess(mapper.writeValueAsString(Map.of("status","completed","output_text",mapper.writeValueAsString(output))),MediaType.APPLICATION_JSON));
        assertEquals(output,provider.generateWorkspacePatch(new WorkspacePatch.Prompt("trusted","untrusted",WorkspacePatch.schema())));server.verify();
    }
    @Test void rejectsOversizedIncompleteMalformedAndUnknownFieldResponses()throws Exception{
        for(String body:List.of("x".repeat(65537),"{\"status\":\"incomplete\"}","{\"status\":\"completed\",\"output_text\":\"not json\"}",
                mapper.writeValueAsString(Map.of("status","completed","output_text","{\"otherFiles\":[]}")))) {
            var props=new AiProperties();props.getOpenai().setApiKey("synthetic-only");var builder=RestClient.builder().baseUrl("https://api.openai.com/v1");
            var server=MockRestServiceServer.bindTo(builder).build();server.expect(anything()).andRespond(withSuccess(body,MediaType.APPLICATION_JSON));
            var provider=new RealOpenAiProvider(props,mapper,builder.build());
            assertThrows(RuntimeException.class,()->provider.generateWorkspacePatch(new WorkspacePatch.Prompt("trusted","data",WorkspacePatch.schema())));server.verify();
        }
    }
    @Test void strictPatchParserRejectsCoercionExtraFieldsAndTrailingModelContent()throws Exception{
        String valid=mapper.writeValueAsString(new WorkspacePatch.Output("PATCH","file",1,"hash","debug=false","설정 검토",List.of("로컬 테스트"),List.of()));
        for(String text:List.of(valid.replace("\"startLine\":1","\"startLine\":\"1\""),valid.replace("\"startLine\":1","\"startLine\":null"),
                valid.replace("\"decision\":\"PATCH\"","\"decision\":\"PATCH\",\"unexpected\":true"),valid+" {}")) {
            var props=new AiProperties();props.getOpenai().setApiKey("synthetic-only");var builder=RestClient.builder().baseUrl("https://api.openai.com/v1");
            var server=MockRestServiceServer.bindTo(builder).build();server.expect(anything()).andRespond(withSuccess(mapper.writeValueAsString(Map.of("status","completed","output_text",text)),MediaType.APPLICATION_JSON));
            var provider=new RealOpenAiProvider(props,mapper,builder.build());assertThrows(RuntimeException.class,()->provider.generateWorkspacePatch(new WorkspacePatch.Prompt("trusted","data",WorkspacePatch.schema())));server.verify();
        }
    }
    @Test void httpFailuresAndTransportTimeoutDoNotRetryOrExposeProviderBody() {
        for (int status : List.of(401, 429, 500)) {
            var props = new AiProperties(); props.getOpenai().setApiKey("synthetic-only");
            var builder = RestClient.builder().baseUrl("https://api.openai.com/v1");
            var server = MockRestServiceServer.bindTo(builder).build();
            server.expect(anything()).andRespond(withStatus(HttpStatus.valueOf(status)).body("synthetic-private-provider-detail"));
            var provider = new RealOpenAiProvider(props, mapper, builder.build());
            var error = assertThrows(RuntimeException.class, () -> provider.generateWorkspacePatch(
                    new WorkspacePatch.Prompt("trusted", "synthetic-data", WorkspacePatch.schema())));
            assertFalse(error.getMessage().contains("synthetic-private-provider-detail"));
            assertTrue(provider.consumeLastTokenUsage().isEmpty());
            server.verify(); // Exactly one request: no retry expectation is registered.
        }
        var props = new AiProperties(); props.getOpenai().setApiKey("synthetic-only");
        var builder = RestClient.builder().baseUrl("https://api.openai.com/v1");
        var server = MockRestServiceServer.bindTo(builder).build();
        server.expect(anything()).andRespond(withException(new java.net.SocketTimeoutException("synthetic-timeout")));
        var provider = new RealOpenAiProvider(props, mapper, builder.build());
        assertThrows(RuntimeException.class, () -> provider.generateWorkspacePatch(new WorkspacePatch.Prompt("trusted", "data", WorkspacePatch.schema())));
        assertTrue(provider.consumeLastTokenUsage().isEmpty()); server.verify();
    }
    @Test void incompleteAndRefusedResponsesAreNotPatchesButReportedUsageRemainsBillable() throws Exception {
        for (var result : List.of(
                Map.of("status", "incomplete", "output_text", "{}"),
                Map.of("status", "completed", "output", List.of(Map.of("type", "message", "content",
                        List.of(Map.of("type", "refusal", "refusal", "synthetic-refusal"))))))) {
            var props = new AiProperties(); props.getOpenai().setApiKey("synthetic-only");
            var builder = RestClient.builder().baseUrl("https://api.openai.com/v1");
            var server = MockRestServiceServer.bindTo(builder).build();
            var body = new LinkedHashMap<String, Object>(result);
            body.put("usage", Map.of("input_tokens", 31, "output_tokens", 7, "total_tokens", 38));
            server.expect(anything()).andRespond(withSuccess(mapper.writeValueAsString(body), MediaType.APPLICATION_JSON));
            var provider = new RealOpenAiProvider(props, mapper, builder.build());
            assertThrows(RuntimeException.class, () -> provider.generateWorkspacePatch(new WorkspacePatch.Prompt("trusted", "data", WorkspacePatch.schema())));
            var usage = provider.consumeLastTokenUsage().orElseThrow();
            assertEquals(38, usage.totalTokens()); assertTrue(usage.billable());
            assertTrue(provider.consumeLastTokenUsage().isEmpty()); server.verify();
        }
    }
    @Test void missingKeyPreventsAnyRequestAndTemplateDoesNotBecomeRealProvider() {
        var props = new AiProperties();
        var builder = RestClient.builder().baseUrl("https://api.openai.com/v1");
        var server = MockRestServiceServer.bindTo(builder).build();
        var provider = new RealOpenAiProvider(props, mapper, builder.build());
        assertFalse(provider.isAvailable());
        assertThrows(IllegalStateException.class, () -> provider.generateWorkspacePatch(new WorkspacePatch.Prompt("trusted", "data", WorkspacePatch.schema())));
        props.getOpenai().setApiKey("synthetic-only");
        assertTrue(provider.isAvailable());
        assertInstanceOf(TemplateAiProvider.class,
                new AiProviderResolver(props, List.of(new TemplateAiProvider(), provider)).resolve());
        server.verify();
    }
}
