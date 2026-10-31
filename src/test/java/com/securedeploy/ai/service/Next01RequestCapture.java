package com.securedeploy.ai.service;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.ai.config.AiProperties;
import com.securedeploy.editing.WorkspacePatch;
import java.nio.file.*;
import java.util.*;
import org.springframework.http.MediaType;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;
/** Local transport capture only: no socket, no real key, no model invocation. */
public final class Next01RequestCapture {
 public static void capture(WorkspacePatch.Prompt prompt,Path root)throws Exception {
  var json=new ObjectMapper();var data=json.readTree(prompt.untrustedData());
  String code=data.path("untrustedCode").asText();
  if(!code.equals("{ready: true, credential: process.env.API_SECRET, count: 12}")&&!code.equals("{ready: true, credential: process.env.API_SECRET, count: 12, secondary: process.env.SUPABASE_SERVICE_ROLE_KEY}"))throw new IllegalStateException("NEXT01_CONTROLLED_SCOPE_ONLY");
  String name=data.path("context").path("removedFields").size()==1?"A_EXPRESS_SINGLE":"B_EXPRESS_MULTI";
  var props=new AiProperties();props.getOpenai().setApiKey("synthetic-local-transport-only");props.getOpenai().setModel("gpt-5.4-mini-2026-03-17");
  var builder=RestClient.builder().baseUrl("https://api.openai.com/v1");var server=MockRestServiceServer.bindTo(builder).build();
  var result=new WorkspacePatch.Output("NEEDS_REVIEW",data.path("fileId").asText(),data.path("startLine").asInt(),data.path("expectedHash").asText(),"","Local transport capture; no model",List.of(),List.of());
  server.expect(requestTo("https://api.openai.com/v1/responses")).andExpect(request->{Files.write(root.resolve(name+"-planned-request.json"),((MockClientHttpRequest)request).getBodyAsBytes());Files.writeString(root.resolve(name+"-prompt.json"),json.writeValueAsString(prompt));}).andRespond(withSuccess(json.writeValueAsString(Map.of("status","completed","output_text",json.writeValueAsString(result))),MediaType.APPLICATION_JSON));
  MockMeteredTransport.provider(props,json,builder.build()).generateWorkspacePatch(prompt);server.verify();
 }
}
