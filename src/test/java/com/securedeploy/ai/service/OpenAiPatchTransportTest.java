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
}
