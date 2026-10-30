package com.securedeploy.ui;
import com.securedeploy.ai.config.*;
import com.securedeploy.ai.service.*;
import com.securedeploy.editing.NpmUpdateGenerator;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
class UiCapabilitiesControllerTest {
 @Test void negotiationDoesNotInvokeModelOrProjectAccess(){
  var properties=new AiProperties();properties.setProvider(AiProviderType.OPENAI);
  var resolver=mock(AiProviderResolver.class);var provider=mock(AiProvider.class);var npm=mock(NpmUpdateGenerator.class);
  when(resolver.resolve()).thenReturn(provider);when(provider.providerType()).thenReturn(AiProviderType.OPENAI);when(provider.isAvailable()).thenReturn(true);when(provider.executionOrigin()).thenReturn("MOCK");when(npm.enabled()).thenReturn(true);
  var result=new UiCapabilitiesController(properties,resolver,npm).capabilities();assertEquals(true,result.get("providerAvailable"));assertEquals("MOCK",result.get("providerOrigin"));assertEquals(true,result.get("dependencyPlans"));
  verify(provider).providerType();verify(provider).isAvailable();verify(provider,atLeastOnce()).executionOrigin();verifyNoMoreInteractions(provider);
 }
 @Test void templateIsNeverAdvertisedAsReadyAi(){
  var properties=new AiProperties();properties.setProvider(AiProviderType.TEMPLATE);var resolver=mock(AiProviderResolver.class);var provider=mock(AiProvider.class);var npm=mock(NpmUpdateGenerator.class);when(resolver.resolve()).thenReturn(provider);
  var result=new UiCapabilitiesController(properties,resolver,npm).capabilities();assertEquals(false,result.get("providerAvailable"));assertEquals(false,result.get("npmGeneration"));assertEquals("UNVERIFIED_PROVIDER",result.get("providerOrigin"));
 }
}
