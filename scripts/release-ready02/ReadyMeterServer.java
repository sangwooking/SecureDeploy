package releasegatefixture;
import com.securedeploy.ai.usage.*;import com.securedeploy.auth.service.*;import org.springframework.boot.builder.SpringApplicationBuilder;import org.springframework.boot.test.context.TestConfiguration;import org.springframework.context.annotation.Bean;import org.springframework.web.bind.annotation.*;import org.springframework.http.ResponseEntity;import java.util.*;
public class ReadyMeterServer {
 @TestConfiguration static class Fixture { @Bean Endpoint endpoint(DurableAiLedger ledger,CurrentUserService user,ReviewAccessService access){return new Endpoint(ledger,user,access);} }
 @RestController static class Endpoint {
  final DurableAiLedger ledger;final CurrentUserService users;final ReviewAccessService access;
  Endpoint(DurableAiLedger l,CurrentUserService u,ReviewAccessService a){ledger=l;users=u;access=a;}
  record Request(String requestId,long review,boolean blockAfterReserve){}
  @PostMapping("/api/test-release-gate/reserve") ResponseEntity<?> reserve(@RequestBody Request r){
   var review=access.findAccessibleReviewWithVulnerabilities(r.review(),"not owned");
   try{String id=ledger.reserve(new AiAdmission.Request(users.currentUserId(),review.getProject().getId(),r.requestId(),"workspace_patch_plan_v1","a".repeat(64),"gpt-5.4-mini-2026-03-17",AiAdmission.hash("control")),"workspace_patch_plan_v1","gpt-5.4-mini-2026-03-17",AiAdmission.hash("control"),32768,2000);if(r.blockAfterReserve()){try{java.nio.file.Files.writeString(java.nio.file.Path.of("/private/tmp/securedeploy-ready02-runtime/RESERVATION_MARKER"),id);Thread.sleep(60000);}catch(Exception interrupted){Thread.currentThread().interrupt();}}return ResponseEntity.ok(Map.of("id",id,"providerCalls",0));}
   catch(IllegalStateException e){return ResponseEntity.status(429).body(Map.of("admitted",false,"providerCalls",0));}
  }
  @PostMapping("/api/test-release-gate/reconcile") ResponseEntity<?> reconcile(){return ResponseEntity.ok(Map.of("changed",ledger.reconcile(),"providerCalls",0));}
 }
 public static void main(String[] args){
  String port=System.getenv("RELEASE_TEST_PORT");if(!Set.of("58234","58235").contains(port)||System.getenv("OPENAI_API_KEY")!=null||System.getenv("SECUREDEPLOY_AI_OPENAI_API_KEY")!=null)throw new IllegalStateException();
  new SpringApplicationBuilder(com.securedeploy.SecureDeployApplication.class,Fixture.class).run("--server.address=127.0.0.1","--server.port="+port,"--spring.datasource.url=jdbc:postgresql://127.0.0.1:58220/ready02_fixture","--spring.datasource.username=ai05_fixture","--spring.datasource.password=","--spring.datasource.driver-class-name=org.postgresql.Driver","--spring.jpa.hibernate.ddl-auto=validate","--spring.sql.init.mode=never","--securedeploy.jwt.secret=ai02-synthetic-isolated-only-signing-key-0000001","--securedeploy.ai.provider=TEMPLATE","--securedeploy.ai.openai.api-key=","--securedeploy.ai.ledger.enabled=true","--securedeploy.ai.ledger.service-daily-usd=0.068","--securedeploy.github.app.enabled=false","--securedeploy.threat-intelligence.enabled=false","--securedeploy.sca.enabled=false","--logging.level.root=OFF","--spring.main.banner-mode=off");
 }
}
