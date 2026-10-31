package com.securedeploy.source;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.SecureDeployApplication;
import com.securedeploy.sca.client.*;
import com.securedeploy.sca.model.*;
import java.nio.file.*;
import java.util.*;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.*;

/** Evaluation-only: replay one captured official OSV snapshot for every case.
 * No mocked source acquisition, no model, no registry or filesystem execution. */
public final class V55ReplayServer {
    @TestConfiguration
    public static class Replay {
        @Bean @Primary VulnerabilityDataSource capturedOfficialFeed() throws Exception {
            var json=new ObjectMapper();
            var feed=json.readTree(Path.of(System.getenv("V55_EVAL_ROOT"),"official-feed.json").toFile());
            var mapper=new OsvAdvisoryMapper();
            return components->{
                var groups=new LinkedHashMap<String,List<DependencyComponent>>();
                for(var c:components)groups.computeIfAbsent(c.identity(),k->new ArrayList<>()).add(c);
                var findings=new ArrayList<DependencyVulnerability>();var complete=new HashSet<String>();
                for(var row:groups.entrySet()){
                    var ids=feed.path("queries").get(row.getKey());if(ids==null||!ids.isArray())continue;
                    var c=row.getValue().get(0);var files=row.getValue().stream().map(DependencyComponent::sourceFile).distinct().toList();boolean valid=true;
                    for(var id:ids){var advisory=feed.path("advisories").get(id.asText());if(advisory==null){valid=false;break;}
                        if(!advisory.hasNonNull("withdrawn"))findings.add(mapper.map(id.asText(),advisory,c,files));}
                    if(valid)complete.add(row.getKey());
                }
                boolean incomplete=complete.size()!=groups.size();
                return new VulnerabilityDataSource.LookupResult(findings,complete,incomplete,incomplete?List.of("OFFICIAL_CAPTURE_MISSING_QUERY"):List.of());
            };
        }
    }
    public static void main(String[] args){
        for(String arg:args)if(arg.startsWith("--spring.datasource.url=")&&!arg.equals("--spring.datasource.url=jdbc:postgresql://127.0.0.1:58550/v55_fixture"))throw new IllegalArgumentException("ISOLATED_DB_ONLY");
        new SpringApplicationBuilder(SecureDeployApplication.class,Replay.class).run(args);
    }
}
