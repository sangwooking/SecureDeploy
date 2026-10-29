package com.securedeploy.evaluation;

import com.securedeploy.SecureDeployApplication;
import java.nio.file.*;
import java.util.Comparator;
import org.springframework.boot.builder.SpringApplicationBuilder;

/** Opt-in real UI/API verification with disposable H2 and unique owned storage. */
public final class StaticRouteBrowserServer {
    public static void main(String[] args) throws Exception {
        if(args.length!=0)throw new IllegalArgumentException("NO_EXTERNAL_CONFIGURATION");
        Path root=Path.of("").toRealPath(), storage=Files.createTempDirectory("securedeploy-route35i-");
        Path classes=Path.of(SecureDeployApplication.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();
        if(!classes.startsWith(root.resolve("build/classes/java/main"))||!Files.isRegularFile(root.resolve("analyzers/typescript/worker.mjs")))
            throw new IllegalStateException("CURRENT_LOCAL_CLASSES_REQUIRED");
        var context=new SpringApplicationBuilder(SecureDeployApplication.class).run(
                "--server.address=127.0.0.1","--server.port=58035",
                "--spring.datasource.url=jdbc:h2:mem:static_route35i;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE",
                "--spring.datasource.username=sa","--spring.datasource.password=","--spring.datasource.driver-class-name=org.h2.Driver",
                "--spring.jpa.hibernate.ddl-auto=create-drop","--spring.sql.init.mode=never","--spring.flyway.enabled=false",
                "--securedeploy.jwt.secret=route35i-synthetic-isolated-signing-key-only-0001",
                "--securedeploy.ai.provider=TEMPLATE","--securedeploy.ai.openai.api-key=","--securedeploy.github.app.enabled=false",
                "--securedeploy.typescript.analyzer-directory="+root.resolve("analyzers/typescript"),
                "--securedeploy.storage.temp-dir="+storage,
                "--securedeploy.sca.enabled=false","--securedeploy.threat-intelligence.enabled=false",
                "--logging.level.root=OFF","--spring.main.banner-mode=off");
        try(var connection=context.getBean(javax.sql.DataSource.class).getConnection()){
            if(!connection.getMetaData().getURL().startsWith("jdbc:h2:mem:static_route35i")){
                context.close();throw new IllegalStateException("ISOLATED_H2_REQUIRED");
            }
        }
        Runtime.getRuntime().addShutdownHook(new Thread(()->{
            context.close();
            try(var paths=Files.walk(storage)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}
            catch(Exception ignored){System.err.println("ROUTE35I_STORAGE_CLEANUP_INCOMPLETE");}
        }));
        System.out.println("ROUTE35I_READY H2_ONLY port=58035 realBeans=true paidAI=false GitHub=false SCA=false");
    }
}
