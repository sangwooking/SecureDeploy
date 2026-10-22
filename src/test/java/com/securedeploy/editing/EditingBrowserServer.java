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
        @Bean @Primary EditingSourceService fixtureSources() {
            var sources = mock(EditingSourceService.class);
            when(sources.github(anyLong(),any())).thenAnswer(i -> List.of(
                    new SourceArchive.Entry("src/example.ts", "export const value = 'original';\n".getBytes(StandardCharsets.UTF_8), false,0100644),
                    new SourceArchive.Entry("assets/example.bin",new byte[]{0,-1,2},false,0100644)));
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
                "--securedeploy.ai.provider=TEMPLATE","--securedeploy.github.app.enabled=false",
                "--securedeploy.storage.temp-dir=/private/tmp/securedeploy-editing-browser",
                "--securedeploy.sca.enabled=false","--securedeploy.threat-intelligence.enabled=false",
                "--logging.level.root=OFF","--spring.main.banner-mode=off");
        try (var connection = context.getBean(javax.sql.DataSource.class).getConnection()) {
            if (!connection.getMetaData().getURL().startsWith("jdbc:h2:mem:editing_browser")) { context.close(); throw new IllegalStateException("H2_ONLY"); }
        }
        var users=context.getBean(UserRepository.class);
        var user=users.saveAndFlush(new UserEntity("editing-browser@example.invalid",context.getBean(org.springframework.security.crypto.password.PasswordEncoder.class).encode("Synthetic-Local-813!"),"Editing fixture"));
        var project=new ProjectEntity("GitHub fixture",ReviewSourceType.GITHUB,"https://github.com/fixture/editing"); project.assignUser(user); context.getBean(ProjectRepository.class).saveAndFlush(project);
        var review=new ReviewEntity("GitHub fixture",ReviewSourceType.GITHUB,"https://github.com/fixture/editing",2,0,100,"READY"); review.assignProject(project);
        review.attachSourceMetadata(new GitHubSourceSnapshot("fixture","editing","https://github.com/fixture/editing","main","a".repeat(40),"aaaaaaa",null,null,null,null,1,0,0,0,List.of()).withAccess(3L,2L,true));
        context.getBean(ReviewRepository.class).saveAndFlush(review);
        System.out.println("EDITING_BROWSER_READY H2_ONLY GITHUB_SOURCE_MOCK port=8085");
    }
}
