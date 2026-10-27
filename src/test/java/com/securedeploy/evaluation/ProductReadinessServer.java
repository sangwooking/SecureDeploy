package com.securedeploy.evaluation;

import com.securedeploy.SecureDeployApplication;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import org.springframework.boot.builder.SpringApplicationBuilder;

/** Local opt-in E2E server: real application beans, disposable H2, no GitHub or paid AI. */
public final class ProductReadinessServer {
    public static void main(String[] args) throws Exception {
        boolean liveSca = args.length == 1 && args[0].equals("LIVE_SCA");
        if (args.length > 1 || args.length == 1 && !liveSca) throw new IllegalArgumentException("READINESS_ARGUMENT");
        Path root = Path.of("").toRealPath();
        Path worker = root.resolve("analyzers/typescript/worker.mjs");
        Path classes = Path.of(SecureDeployApplication.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();
        if (!Files.isRegularFile(worker) || !Files.isRegularFile(root.resolve("frontend/package.json")))
            throw new IllegalStateException("SOURCE_ROOT_REQUIRED");
        if (!classes.startsWith(root.resolve("build/classes/java/main")))
            throw new IllegalStateException("CURRENT_BUILD_CLASSES_REQUIRED");
        var context = new SpringApplicationBuilder(SecureDeployApplication.class).run(
                "--server.address=127.0.0.1", "--server.port=58033",
                "--spring.datasource.url=jdbc:h2:mem:product_readiness33;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE",
                "--spring.datasource.username=sa", "--spring.datasource.password=", "--spring.datasource.driver-class-name=org.h2.Driver",
                "--spring.jpa.hibernate.ddl-auto=create-drop", "--spring.sql.init.mode=never", "--spring.flyway.enabled=false",
                "--securedeploy.jwt.secret=readiness33-synthetic-isolated-signing-key-only-0001",
                "--securedeploy.ai.provider=TEMPLATE", "--securedeploy.ai.openai.api-key=", "--securedeploy.github.app.enabled=false",
                "--securedeploy.typescript.analyzer-directory=" + root.resolve("analyzers/typescript"),
                "--securedeploy.storage.temp-dir=/private/tmp/securedeploy-product33-input",
                "--securedeploy.sca.enabled=" + liveSca, "--securedeploy.threat-intelligence.enabled=false",
                "--logging.level.root=OFF", "--spring.main.banner-mode=off");
        try (var connection = context.getBean(javax.sql.DataSource.class).getConnection()) {
            if (!connection.getMetaData().getURL().startsWith("jdbc:h2:mem:product_readiness33")) {
                context.close(); throw new IllegalStateException("ISOLATED_DATABASE_REQUIRED");
            }
        }
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(worker)));
        System.out.println("READINESS33_READY H2_ONLY port=58033 mockBeans=false paidAI=false liveSca=" + liveSca
                + " sourceRoot=" + root + " applicationClasses=" + classes + " workerSha256=" + hash);
    }
}
