package com.securedeploy.ai.service;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.ai.config.AiProperties;
import com.securedeploy.ai.usage.*;
import com.securedeploy.editing.WorkspacePatch;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
class ReleaseAdmissionTransportTest {
 @Test void noConsentBlocksEveryRealStructuredTransportAndProductionConstructorFailsClosed(){
  var props=new AiProperties();props.getOpenai().setApiKey("synthetic-only");var mapper=new ObjectMapper();
  assertFalse(new RealOpenAiProvider(props,mapper).isAvailable());
  var builder=RestClient.builder();var server=MockRestServiceServer.bindTo(builder).build();var provider=new RealOpenAiProvider(props,mapper,builder.build());
  var gate=mock(DurableAiLedger.class);when(gate.enabled()).thenReturn(true);when(gate.reserve(any(),anyString(),anyString(),anyString(),anyInt(),anyInt())).thenThrow(new IllegalStateException("consent required"));provider.configureLedger(gate);
  var prompt=new WorkspacePatch.Prompt("instructions","data",WorkspacePatch.schema());
  assertThrows(RuntimeException.class,()->provider.generateWorkspacePatch(prompt));
  assertThrows(RuntimeException.class,()->provider.generateWorkspacePatchPlan(prompt));
  assertThrows(RuntimeException.class,()->provider.generateDependencyAdvice(prompt));
  assertThrows(RuntimeException.class,()->provider.generateSemanticReview(List.of(),new com.securedeploy.ai.semantic.SemanticPrompt("instructions","data",2000)));
  server.verify();verify(gate,times(4)).reserve(isNull(),anyString(),anyString(),anyString(),eq(32768),eq(2000));
 }
 @Test void settlementFailureIsUncertainAndOneHttpRequestOnly()throws Exception{
  var props=new AiProperties();props.getOpenai().setApiKey("synthetic-only");var mapper=new ObjectMapper();var builder=RestClient.builder().baseUrl("https://api.openai.com/v1");
  var server=MockRestServiceServer.bindTo(builder).build();var provider=new RealOpenAiProvider(props,mapper,builder.build());var gate=mock(DurableAiLedger.class);
  when(gate.enabled()).thenReturn(true);when(gate.reserve(any(),anyString(),anyString(),anyString(),anyInt(),anyInt())).thenReturn("once");
  doThrow(new IllegalStateException()).when(gate).complete(eq("once"),any());provider.configureLedger(gate);
  server.expect(anything()).andRespond(withSuccess("{\"status\":\"completed\",\"output_text\":\"{}\",\"usage\":{\"input_tokens\":10,\"output_tokens\":2}}",MediaType.APPLICATION_JSON));
  assertThrows(RuntimeException.class,()->provider.generateWorkspacePatch(new WorkspacePatch.Prompt("i","d",WorkspacePatch.schema())));
  verify(gate).sending("once");verify(gate).uncertain("once");server.verify();
 }
}
