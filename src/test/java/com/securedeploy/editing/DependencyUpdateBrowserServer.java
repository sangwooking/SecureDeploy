package com.securedeploy.editing;

import com.fasterxml.jackson.databind.*;
import com.securedeploy.SecureDeployApplication;
import com.securedeploy.sca.client.*;
import com.securedeploy.sca.model.*;
import com.securedeploy.persistence.entity.*;
import com.securedeploy.persistence.repository.*;
import com.securedeploy.github.model.GitHubSourceSnapshot;
import com.securedeploy.review.model.ReviewSourceType;
import com.securedeploy.review.model.ScanMode;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.*;
import static org.mockito.Mockito.*;

/** Opt-in pinned real input replay. Source and feed stay outside Git; no outbound model or project execution. */
public final class DependencyUpdateBrowserServer {
    static Path root;
    static final ObjectMapper json=new ObjectMapper().findAndRegisterModules();
    static List<SourceArchive.Entry> entries(String name) throws Exception {
        if(!Set.of("runwhen","urisai","semantic-risk","semantic-normal","semantic-unknown","semantic-duplicate","semantic-invalid","patch-express","patch-settings","patch-deno","patch-unknown","ux-local-storage","ux-http-tests","ux-next","patch-express-multi","patch-express-pair","patch-express-pair-confirmed","patch-independent-one","patch-independent-two","patch-independent-three","patch03-layout").contains(name))throw new IllegalArgumentException();
        Path dir=root.resolve(name).resolve("before");var entries=new ArrayList<SourceArchive.Entry>();
        try(var files=Files.walk(dir)){for(Path p:files.filter(Files::isRegularFile).sorted().toList()){
            if(Files.isSymbolicLink(p))throw new IllegalArgumentException("NO_SYMLINKS");
            entries.add(new SourceArchive.Entry(dir.relativize(p).toString().replace('\\','/'),Files.readAllBytes(p),false,0100644));
        }}
        return entries;
    }
    @TestConfiguration
    public static class Replay {
        @Bean @Primary VulnerabilityDataSource frozenOfficialFeed() throws Exception {
            var feed=json.readTree(root.resolve("official-feed.json").toFile());var mapper=new OsvAdvisoryMapper();
            return components->{
                var grouped=new LinkedHashMap<String,List<DependencyComponent>>();
                for(var c:components)grouped.computeIfAbsent(c.identity(),k->new ArrayList<>()).add(c);
                var findings=new ArrayList<DependencyVulnerability>();var analyzed=new HashSet<String>();
                for(var row:grouped.entrySet()){
                    var ids=feed.path("queries").get(row.getKey());if(ids==null)continue;
                    var c=row.getValue().get(0);var paths=row.getValue().stream().map(DependencyComponent::sourceFile).distinct().toList();
                    boolean complete=true;
                    for(var id:ids){var advisory=feed.path("advisories").get(id.asText());
                        if(advisory==null||advisory.hasNonNull("withdrawn")){complete=false;break;}
                        findings.add(mapper.map(id.asText(),advisory,c,paths));
                    }
                    if(complete)analyzed.add(row.getKey());
                }
                boolean incomplete=analyzed.size()!=grouped.size();
                return new VulnerabilityDataSource.LookupResult(findings,analyzed,incomplete,incomplete?List.of("CAPTURED_FEED_INPUT_MISMATCH"):List.of());
            };
        }
        @Bean @Primary EditingSourceService capturedSource(){
            var source=mock(EditingSourceService.class);
            when(source.github(anyLong(),any())).thenAnswer(i->entries(((GitHubSourceSnapshot)i.getArgument(1)).repository()));
            return source;
        }
    }
    public static void main(String[] args) throws Exception {
        root=Path.of(System.getenv().getOrDefault("SECUREDEPLOY_AI02_INPUT","/private/tmp/securedeploy-ai02-real")).toRealPath();
        if(!Files.isRegularFile(root.resolve("official-feed.json")))throw new IllegalArgumentException("CAPTURE_REQUIRED");
        boolean phase5="1".equals(System.getenv("SECUREDEPLOY_AI05_PG"));
        boolean phase4="1".equals(System.getenv("SECUREDEPLOY_AI04"));
        boolean advice="1".equals(System.getenv("SECUREDEPLOY_AI03_ADVICE"));
        boolean live="1".equals(System.getenv("SECUREDEPLOY_AI03_LIVE"));
        if(live)throw new IllegalStateException("FIX01_NO_PAID_CALLS");
        if(phase4&&live)throw new IllegalStateException("AI04_MODEL_CALL_NOT_APPROVED");
        var app=advice?new SpringApplicationBuilder(SecureDeployApplication.class,Replay.class,DependencyAdviceBrowserServer.AdviceFixture.class):new SpringApplicationBuilder(SecureDeployApplication.class,Replay.class);
        var context=app.run(
                "--server.address=127.0.0.1","--server.port="+(phase4?58124:advice?58043:58042),
                "--spring.datasource.url="+(phase5?"jdbc:postgresql://127.0.0.1:58057/patch03_mock":"jdbc:h2:mem:ai02_isolated;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE"),
                "--spring.datasource.username="+(phase5?"ai05_fixture":"sa"),"--spring.datasource.password=","--spring.datasource.driver-class-name="+(phase5?"org.postgresql.Driver":"org.h2.Driver"),
                "--spring.jpa.hibernate.ddl-auto="+(phase5?("1".equals(System.getenv("SECUREDEPLOY_FIX01_RESTART"))?"validate":"update"):"create-drop"),"--spring.sql.init.mode=never",
                "--securedeploy.jwt.secret=ai02-synthetic-isolated-only-signing-key-0000001",
                "--securedeploy.ai.provider="+(advice?"OPENAI":"TEMPLATE"),"--securedeploy.ai.openai.model="+(live?"gpt-5.4-mini":"mock-fixture-no-external"),"--securedeploy.ai.openai.api-key=","--securedeploy.github.app.enabled=false",
                "--securedeploy.storage.temp-dir="+root.resolve("api-temp"),"--securedeploy.sca.enabled=true","--securedeploy.editing.npm-generation-enabled="+(phase4&&"1".equals(System.getenv("SECUREDEPLOY_AI04_NPM"))),
                "--securedeploy.threat-intelligence.enabled=false","--logging.level.root=OFF","--spring.main.banner-mode=off");
        try(var db=context.getBean(javax.sql.DataSource.class).getConnection()){
            if(!(phase5?db.getMetaData().getURL().equals("jdbc:postgresql://127.0.0.1:58057/patch03_mock"):db.getMetaData().getURL().startsWith("jdbc:h2:mem:ai02_isolated"))){context.close();throw new IllegalStateException("H2_ONLY");}
        }
        if("1".equals(System.getenv("SECUREDEPLOY_FIX01_RESTART"))){
            if(!phase5||!phase4)throw new IllegalStateException("FIX01_ISOLATED_RESTART_ONLY");
            if("1".equals(System.getenv("SECUREDEPLOY_PATCH03_LAYOUT"))){
                var users=context.getBean(UserRepository.class);String name="patch03-layout";
                if(!users.existsByEmail(name+"@example.invalid")){
                    var actor=users.saveAndFlush(new UserEntity(name+"@example.invalid",context.getBean(org.springframework.security.crypto.password.PasswordEncoder.class).encode("Synthetic-AI02-135!"),"CONTROL SYNTHETIC"));
                    var project=new ProjectEntity("CONTROL "+name,ReviewSourceType.GITHUB,"https://github.com/fixture/"+name);project.assignUser(actor);context.getBean(ProjectRepository.class).saveAndFlush(project);
                    var outcome=context.getBean(com.securedeploy.review.service.SecurityReviewFacade.class).analyzeWorkspace("CONTROL "+name,root.resolve(name).resolve("before"));
                    var metadata=new GitHubSourceSnapshot("fixture",name,project.getRepositoryUrl(),"main","a".repeat(40),"aaaaaaa",null,null,null,null,1,0,0,0,List.of("PATCH03_INDEPENDENT_SYNTHETIC")).withAccess(3L,2L,true);
                    var saved=context.getBean(com.securedeploy.persistence.service.ReviewPersistenceService.class).saveReview(project,outcome.response().withSourceMetadata(metadata),ReviewSourceType.GITHUB,project.getRepositoryUrl(),outcome.snippetGroup(),outcome.intelligence(),ScanMode.STANDARD,outcome.comparisonContext());context.getBean(com.securedeploy.project.progress.ReviewProgressService.class).complete(saved);
                }
            }
            Runtime.getRuntime().addShutdownHook(new Thread(context::close));System.out.println("FIX01_RESTART_READY PERSISTED_DB port=58124");return;
        }
        var users=context.getBean(UserRepository.class);var password=context.getBean(org.springframework.security.crypto.password.PasswordEncoder.class).encode("Synthetic-AI02-135!");
        var user=users.saveAndFlush(new UserEntity("ai02-owner@example.invalid",password,"AI02 local evaluation"));
        users.saveAndFlush(new UserEntity("ai02-other@example.invalid",password,"AI02 other user"));
        var plan=json.readTree(root.resolve("pinned-input.json").toFile());
        for(var row:plan.path("projects")){
            String name=row.path("projectId").asText().replace("nemanic3--","");
            var project=new ProjectEntity(name,ReviewSourceType.GITHUB,"https://github.com/nemanic3/"+name);project.assignUser(user);context.getBean(ProjectRepository.class).saveAndFlush(project);
            var outcome=context.getBean(com.securedeploy.review.service.SecurityReviewFacade.class).analyzeWorkspace(name,root.resolve(name).resolve("before"));
            String sha=row.path("commitSha").asText();
            var metadata=new GitHubSourceSnapshot("nemanic3",name,project.getRepositoryUrl(),"main",sha,sha.substring(0,7),null,null,null,null,1,0,0,0,List.of("CAPTURED_PINNED_SOURCE_LOCAL_REPLAY")).withAccess(3L,2L,true);
            var saved=context.getBean(com.securedeploy.persistence.service.ReviewPersistenceService.class).saveReview(project,outcome.response().withSourceMetadata(metadata),ReviewSourceType.GITHUB,project.getRepositoryUrl(),outcome.snippetGroup(),outcome.intelligence(),ScanMode.STANDARD,outcome.comparisonContext());
            context.getBean(com.securedeploy.project.progress.ReviewProgressService.class).complete(saved);
        }
        if(phase4)for(String name:(phase5?java.util.List.of("semantic-risk","semantic-normal","semantic-unknown","semantic-duplicate","semantic-invalid","patch-express","patch-settings","patch-deno","patch-unknown","ux-local-storage","ux-http-tests","ux-next","patch-express-multi","patch-express-pair","patch-express-pair-confirmed","patch-independent-one","patch-independent-two","patch-independent-three"):java.util.List.of("semantic-risk","semantic-normal","semantic-unknown","semantic-duplicate","semantic-invalid"))){
            var actor=users.saveAndFlush(new UserEntity(name+"@example.invalid",password,"CONTROL SYNTHETIC"));
            var project=new ProjectEntity("CONTROL "+name,ReviewSourceType.GITHUB,"https://github.com/fixture/"+name);project.assignUser(actor);context.getBean(ProjectRepository.class).saveAndFlush(project);
            var outcome=context.getBean(com.securedeploy.review.service.SecurityReviewFacade.class).analyzeWorkspace("CONTROL "+name,root.resolve(name).resolve("before"));
            var metadata=new GitHubSourceSnapshot("fixture",name,project.getRepositoryUrl(),"main","a".repeat(40),"aaaaaaa",null,null,null,null,1,0,0,0,List.of("CONTROLLED_SYNTHETIC_NOT_REAL_TP")).withAccess(3L,2L,true);
            var saved=context.getBean(com.securedeploy.persistence.service.ReviewPersistenceService.class).saveReview(project,outcome.response().withSourceMetadata(metadata),ReviewSourceType.GITHUB,project.getRepositoryUrl(),outcome.snippetGroup(),outcome.intelligence(),ScanMode.STANDARD,outcome.comparisonContext());context.getBean(com.securedeploy.project.progress.ReviewProgressService.class).complete(saved);
        }
        Runtime.getRuntime().addShutdownHook(new Thread(context::close));
        System.out.println("DEPENDENCY_READY "+(phase5?"ISOLATED_POSTGRES":"H2_ONLY")+" port="+(phase4?58124:advice?58043:58042)+" provider="+(advice?(live?"LIVE_MAX_TWO_PUBLIC_METADATA_ONLY":"MOCK"):"TEMPLATE")+" OFFICIAL_FEED_REPLAY PINNED_REAL_SOURCE");
    }
}
