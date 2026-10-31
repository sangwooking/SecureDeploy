package com.securedeploy.ai.service;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.ai.config.AiProperties;
import com.securedeploy.ai.usage.DurableAiLedger;
import org.springframework.web.client.RestClient;
/** Transport-format tests use an explicit fake meter and MockRestServiceServer, never a production bypass. */
final class MockMeteredTransport {
 static RealOpenAiProvider provider(AiProperties props,ObjectMapper mapper,RestClient client){
  var p=new RealOpenAiProvider(props,mapper,client);var meter=mock(DurableAiLedger.class);
  when(meter.enabled()).thenReturn(true);when(meter.reserve(any(),anyString(),anyString(),anyString(),anyInt(),anyInt())).thenReturn("mock-transport-request");p.configureLedger(meter);return p;
 }
}
