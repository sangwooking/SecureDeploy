package com.securedeploy.editing;
import com.securedeploy.ai.config.*;import com.securedeploy.ai.service.*;import org.springframework.boot.builder.SpringApplicationBuilder;import org.springframework.boot.test.context.TestConfiguration;import org.springframework.context.annotation.*;import java.nio.file.*;import java.util.*;import java.lang.reflect.*;
public final class ReadyRestorePeer {
 @TestConfiguration public static class Fixture{
  @Bean @Primary AiProviderResolver noModelResolver(AiProperties p){
   var provider=(AiProvider)Proxy.newProxyInstance(AiProvider.class.getClassLoader(),new Class<?>[]{AiProvider.class},(proxy,method,args)->{
    if(method.getDeclaringClass()==Object.class)return switch(method.getName()){case "toString"->"EPIC01 no-model preview provider";case "hashCode"->System.identityHashCode(proxy);case "equals"->proxy==args[0];default->null;};
    return switch(method.getName()){case "providerType"->AiProviderType.OPENAI;case "isAvailable"->true;case "executionOrigin"->"NO_MODEL_PREVIEW";case "consumeLastTokenUsage"->Optional.empty();default->throw new IllegalStateException("EPIC01_PAID_AND_MOCK_GENERATION_DISABLED");};
   });return new AiProviderResolver(p,List.of(provider,new TemplateAiProvider()));
  }
 }
 public static void main(String[]args)throws Exception{
  if(System.getenv("OPENAI_API_KEY")!=null||System.getenv("SECUREDEPLOY_AI_OPENAI_API_KEY")!=null||System.getenv("SECUREDEPLOY_EDITING_PERSISTENCE_KEY")!=null)throw new IllegalStateException("UNSET_KEYS_FOR_BASELINE");
  DependencyUpdateBrowserServer.root=Path.of("/private/tmp/securedeploy-live03-inputs");
  String mode=System.getenv().getOrDefault("READY_MODE","normal");
  var app=mode.equals("mock")?new SpringApplicationBuilder(com.securedeploy.SecureDeployApplication.class,DependencyUpdateBrowserServer.Replay.class,DependencyAdviceBrowserServer.AdviceFixture.class):new SpringApplicationBuilder(com.securedeploy.SecureDeployApplication.class,DependencyUpdateBrowserServer.Replay.class);
  var c=app.run("--spring.profiles.active="+(mode.equals("compatible")?"release-compatible":mode.equals("recovery")?"release-recovery":"default"),"--securedeploy.editing.persistence.enabled="+!mode.equals("recovery"),"--securedeploy.editing.persistence.key-id=epic01-test-v1","--securedeploy.editing.persistence.key-file="+System.getenv().getOrDefault("RELEASE_TEST_KEY_FILE","/private/tmp/securedeploy-ready02-runtime/key/test-only.key"),"--server.address=127.0.0.1","--server.port=58233","--spring.datasource.url=jdbc:postgresql://127.0.0.1:58220/ready02_restore","--spring.datasource.username=ai05_fixture","--spring.datasource.password=","--spring.datasource.driver-class-name=org.postgresql.Driver","--spring.jpa.hibernate.ddl-auto=validate","--spring.datasource.hikari.connection-timeout=3000","--spring.sql.init.mode=never","--securedeploy.jwt.secret=ai02-synthetic-isolated-only-signing-key-0000001","--securedeploy.ai.provider="+(mode.equals("mock")?"OPENAI":"TEMPLATE"),"--securedeploy.ai.openai.model=mock-fixture-no-external","--securedeploy.ai.openai.api-key=","--securedeploy.github.app.enabled=false","--securedeploy.storage.temp-dir=/private/tmp/securedeploy-live03-inputs/api-temp-mock","--securedeploy.sca.enabled=true","--securedeploy.editing.npm-generation-enabled=false","--securedeploy.threat-intelligence.enabled=false","--logging.level.root=OFF","--spring.main.banner-mode=off");
  try(var db=c.getBean(javax.sql.DataSource.class).getConnection()){if(!db.getMetaData().getURL().equals("jdbc:postgresql://127.0.0.1:58220/ready02_restore"))throw new IllegalStateException("ISOLATED_DB_REQUIRED");}
  Runtime.getRuntime().addShutdownHook(new Thread(c::close));System.out.println("EPIC01_MOCK_READY port=58233 realModelCalls=BLOCKED");
 }
}
