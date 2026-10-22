package com.securedeploy.evaluation;

import com.securedeploy.SecureDeployApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

/** Opt-in localhost fixture server. No production environment or user database. */
public final class SummaryBrowserServer {
    public static void main(String[] args)throws Exception{
        var context=new SpringApplicationBuilder(SecureDeployApplication.class).run(
                "--server.address=127.0.0.1","--server.port=8085",
                "--spring.datasource.url=jdbc:h2:mem:summary_browser;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE",
                "--spring.datasource.username=sa","--spring.datasource.password=","--spring.datasource.driver-class-name=org.h2.Driver",
                "--spring.jpa.hibernate.ddl-auto=create-drop","--spring.sql.init.mode=never","--spring.flyway.enabled=false",
                "--securedeploy.jwt.secret=summary-browser-isolated-synthetic-signing-key-0001",
                "--securedeploy.ai.provider=TEMPLATE","--securedeploy.github.app.enabled=false",
                "--securedeploy.storage.temp-dir=/private/tmp/securedeploy-summary-browser",
                "--securedeploy.sca.enabled=false","--securedeploy.threat-intelligence.enabled=false",
                "--logging.level.root=OFF","--spring.main.banner-mode=off");
        try(var connection=context.getBean(javax.sql.DataSource.class).getConnection()){
            if(!connection.getMetaData().getURL().startsWith("jdbc:h2:mem:summary_browser")){
                context.close();throw new IllegalStateException("ISOLATED_DATABASE_REQUIRED");
            }
        }
        System.out.println("SUMMARY_BROWSER_READY H2_ONLY port=8085");
    }
}
