package com.securedeploy.evaluation;

import com.fasterxml.jackson.databind.*;
import com.securedeploy.review.service.SecurityReviewFacade;
import com.securedeploy.analysis.typescript.TypeScriptServerAnalyzer;
import com.securedeploy.project.service.ProjectScanner;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;

/** Optional retained, previously observed freeze assets. No sources are checked into this repository. */
@SpringBootTest(properties={"securedeploy.ai.provider=TEMPLATE","securedeploy.sca.enabled=false","securedeploy.threat-intelligence.enabled=false"})
class WorkspaceEngineRegressionTest {
    @Autowired SecurityReviewFacade facade;
    @Autowired ObjectMapper json;
    @Autowired ProjectScanner scanner;
    @Autowired TypeScriptServerAnalyzer ts;
    @Test void retainedFreezeAssetsKeepRuleAndStructuralSignalsThroughWorkspacePipeline() throws Exception {
        String configured=System.getenv("SECUREDEPLOY_REGRESSION_ROOT");
        assumeTrue(configured!=null,"External retained benchmark assets were not supplied.");
        Path root=Path.of(configured).toRealPath();
        var plan=json.readTree(root.resolve("application-plan.json").toFile());
        var baseline=json.readTree(root.resolve("closeout-results.json").toFile());
        int completed=0;
        for(var project:plan.path("projects")) {
            String id=project.path("projectId").asText();
            Path source=root.resolve("sources").resolve(id).toRealPath();
            ApplicationEvaluationRunner.verify(root,source,project);
            var expected=java.util.stream.StreamSupport.stream(baseline.path("projects").spliterator(),false)
                    .filter(p->p.path("projectId").asText().equals(id)).findFirst().orElseThrow().at("/runs/0");
            var result=facade.analyzeWorkspace("retained-regression",source);
            var actual=new TreeSet<String>();
            result.response().vulnerabilities().forEach(f->actual.add(f.ruleId()+"|"+f.filePath()+"|"+f.line()));
            var old=new TreeSet<String>();expected.path("filtered").forEach(f->old.add(f.path("ruleId").asText()+"|"+f.path("filePath").asText()+"|"+f.path("line").asInt()));
            assertEquals(old,actual,"Saved freeze Rule/FPR signals must not change");
            assertEquals(expected.path("securityScore").asInt(),result.response().securityScore());
            // Compare only deterministic security candidates, not timestamps or execution timing.
            assertEquals(withoutVersionIdentity(expected.at("/typescript/validatedFindings")),withoutVersionIdentity(json.valueToTree(result.response().serverAnalysis().validatedFindings())));
            assertEquals(expected.at("/typescript/supabaseAnalysis/findings"),json.valueToTree(ts.analyze(scanner.scan(source)).supabaseAnalysis().findings()));
            completed++;
        }
        assertEquals(4,completed);
    }
    private JsonNode withoutVersionIdentity(JsonNode findings) {
        var copy=findings.deepCopy();
        // Versioned IDs intentionally change. Preserve comparisons of every evidence/location/policy field.
        for(var finding:copy)if(finding instanceof com.fasterxml.jackson.databind.node.ObjectNode object){object.remove("findingId");object.remove("analyzerVersion");}
        return copy;
    }
}
