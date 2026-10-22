package com.securedeploy.editing;

import com.securedeploy.SecureDeployApplication;
import com.securedeploy.persistence.entity.*;
import com.securedeploy.persistence.repository.*;
import com.securedeploy.github.model.GitHubSourceSnapshot;
import com.securedeploy.review.model.ReviewSourceType;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.*;
import static org.mockito.Mockito.*;

/** Isolated test-only source provider; no outbound GitHub or AI access. */
public final class EditingBrowserServer {
    @TestConfiguration
    public static class Fixture {
        @Bean @Primary com.securedeploy.ai.service.AiProviderResolver fixturePatchProvider(com.securedeploy.ai.config.AiProperties properties,com.fasterxml.jackson.databind.ObjectMapper mapper) {
            var provider=mock(com.securedeploy.ai.service.AiProvider.class);
            when(provider.providerType()).thenReturn(com.securedeploy.ai.config.AiProviderType.OPENAI);when(provider.isAvailable()).thenReturn(true);
            when(provider.consumeLastTokenUsage()).thenReturn(Optional.empty());
            when(provider.generateWorkspacePatch(any())).thenAnswer(i->{
                var prompt=(WorkspacePatch.Prompt)i.getArgument(0);var data=mapper.readTree(prompt.untrustedData());String before=data.path("untrustedCode").asText();
                return new WorkspacePatch.Output("PATCH",data.path("fileId").asText(),data.path("startLine").asInt(),data.path("expectedHash").asText(),before.equals("debug=true")?"debug=false":"server.error.include-stacktrace=never",
                        "MOCK: 설정 값만 변경하는 통제 제안입니다.",List.of("로컬 설정 테스트 후 재검사하세요."),List.of("실제 모델 호출과 품질 평가는 수행하지 않았습니다."));
            });
            return new com.securedeploy.ai.service.AiProviderResolver(properties,List.of(provider,new com.securedeploy.ai.service.TemplateAiProvider()));
        }
        @Bean @Primary WorkspacePatchService fixturePatchService(EditingWorkspaceService workspaces,com.securedeploy.ai.service.AiProviderResolver resolver,
                com.securedeploy.ai.config.AiProperties properties,com.securedeploy.auth.service.CurrentUserService users,
                com.fasterxml.jackson.databind.ObjectMapper mapper,com.securedeploy.ai.usage.AiUsageTracker usage) {
            var tick=new java.util.concurrent.atomic.AtomicLong();
            var clock=new java.time.Clock(){public java.time.ZoneId getZone(){return java.time.ZoneOffset.UTC;}public java.time.Clock withZone(java.time.ZoneId z){return this;}
                public java.time.Instant instant(){return java.time.Instant.parse("2026-01-01T00:00:00Z").plusSeconds(tick.getAndAdd(11));}};
            return new WorkspacePatchService(workspaces,resolver,properties,users,mapper,usage,clock);
        }
        @Bean @Primary EditingSourceService fixtureSources() {
            var sources = mock(EditingSourceService.class);
            when(sources.github(anyLong(),any())).thenAnswer(i -> List.of(
                    new SourceArchive.Entry("src/example.ts", "export const value = 'original';\n".getBytes(StandardCharsets.UTF_8), false,0100644),
                    new SourceArchive.Entry("assets/example.bin",new byte[]{0,-1,2},false,0100644),
                    new SourceArchive.Entry("application.properties","debug=true\nserver.error.include-stacktrace=always\n".getBytes(StandardCharsets.UTF_8),false,0100644)));
            return sources;
        }
    }
    public static void main(String[] args) throws Exception {
        var context = new SpringApplicationBuilder(SecureDeployApplication.class, Fixture.class).run(
                "--server.address=127.0.0.1","--server.port=8085",
                "--spring.datasource.url=jdbc:h2:mem:editing_browser;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE",
                "--spring.datasource.username=sa","--spring.datasource.password=","--spring.datasource.driver-class-name=org.h2.Driver",
                "--spring.jpa.hibernate.ddl-auto=create-drop","--spring.sql.init.mode=never","--spring.flyway.enabled=false",
                "--securedeploy.jwt.secret=editing-browser-synthetic-isolated-signing-key-0001",
                "--securedeploy.ai.provider=OPENAI","--securedeploy.ai.openai.model=mock-fixture-no-external","--securedeploy.ai.openai.api-key=","--securedeploy.github.app.enabled=false",
                "--securedeploy.storage.temp-dir=/private/tmp/securedeploy-editing-browser",
                "--securedeploy.sca.enabled=false","--securedeploy.threat-intelligence.enabled=false",
                "--logging.level.root=OFF","--spring.main.banner-mode=off");
        try (var connection = context.getBean(javax.sql.DataSource.class).getConnection()) {
            if (!connection.getMetaData().getURL().startsWith("jdbc:h2:mem:editing_browser")) { context.close(); throw new IllegalStateException("H2_ONLY"); }
        }
        var users=context.getBean(UserRepository.class);
        for (String email : List.of("editing-browser@example.invalid", "scan-1440@example.invalid", "scan-390@example.invalid", "scan-320@example.invalid")) {
        var user=users.saveAndFlush(new UserEntity(email,context.getBean(org.springframework.security.crypto.password.PasswordEncoder.class).encode("Synthetic-Local-813!"),"Editing fixture"));
        var project=new ProjectEntity("GitHub fixture",ReviewSourceType.GITHUB,"https://github.com/fixture/editing"); project.assignUser(user); context.getBean(ProjectRepository.class).saveAndFlush(project);
        var root=java.nio.file.Files.createTempDirectory("securedeploy-editing-fixture-");
        try {
            java.nio.file.Files.writeString(root.resolve("application.properties"),"debug=true\nserver.error.include-stacktrace=always\n");
            java.nio.file.Files.createDirectories(root.resolve("src"));java.nio.file.Files.writeString(root.resolve("src/example.ts"),"export const value = 'original';\n");
            java.nio.file.Files.createDirectories(root.resolve("assets"));java.nio.file.Files.write(root.resolve("assets/example.bin"),new byte[]{0,-1,2});
            var outcome=context.getBean(com.securedeploy.review.service.SecurityReviewFacade.class).analyzeWorkspace("GitHub fixture",root);
            var metadata=new GitHubSourceSnapshot("fixture","editing",project.getRepositoryUrl(),"main","a".repeat(40),"aaaaaaa",null,null,null,null,1,0,0,0,List.of()).withAccess(3L,2L,true);
            var saved=context.getBean(com.securedeploy.persistence.service.ReviewPersistenceService.class).saveReview(project,
                    outcome.response().withSourceMetadata(metadata),ReviewSourceType.GITHUB,project.getRepositoryUrl(),outcome.snippetGroup(),outcome.intelligence(),
                    com.securedeploy.review.model.ScanMode.STANDARD,outcome.comparisonContext());
            context.getBean(com.securedeploy.project.progress.ReviewProgressService.class).complete(saved);
        } finally {com.securedeploy.global.util.FileUtils.deleteRecursively(root);}
        }
        System.out.println("EDITING_BROWSER_READY H2_ONLY GITHUB_SOURCE_MOCK port=8085");
    }
}
