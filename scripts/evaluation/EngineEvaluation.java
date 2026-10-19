import com.securedeploy.SecureDeployApplication;
import com.securedeploy.project.service.ProjectScanner;
import com.securedeploy.rule.engine.*;
import com.securedeploy.rule.filter.FalsePositiveAnalyzer;
import com.securedeploy.analysis.python.PythonServerAnalyzer;
import com.securedeploy.analysis.typescript.TypeScriptServerAnalyzer;
import com.securedeploy.analysis.deployment.DeploymentAnalyzer;
import com.securedeploy.sca.parser.ScaManifestCollector;
import com.fasterxml.jackson.databind.*;
import org.springframework.boot.builder.SpringApplicationBuilder;
import java.nio.file.*;
import java.util.*;

/** Operator-owned evaluation only. No acquisition, AI, OSV or target execution. */
class EngineEvaluation {
    public static void main(String[] args) throws Exception {
        var mapper=new ObjectMapper().findAndRegisterModules();
        Path root=Path.of(args[0]).toRealPath();
        Path manifestPath=root.resolve("manifest.json");
        if(Files.size(manifestPath)>1_000_000)throw new IllegalArgumentException("Evaluation manifest limit exceeded");
        var manifest=mapper.readTree(manifestPath.toFile());
        var results=new ArrayList<Object>();
        try(var context=new SpringApplicationBuilder(SecureDeployApplication.class).run(
                "--server.port=0","--spring.jpa.hibernate.ddl-auto=validate","--spring.sql.init.mode=never",
                "--spring.datasource.hikari.connection-init-sql=SET default_transaction_read_only=on",
                "--logging.level.root=OFF","--spring.main.banner-mode=off","--securedeploy.ai.provider=template")) {
            if(!manifest.path("cases").isArray()||manifest.path("cases").size()>100)
                throw new IllegalArgumentException("Evaluation case limit exceeded");
            for(var test:manifest.path("cases")) {
                String id=test.path("id").asText();
                Path directory=root.resolve(id).normalize();
                if(!directory.toRealPath().startsWith(root)||!id.matches("[A-Za-z0-9_-]+"))throw new IllegalArgumentException("Invalid evaluation case path");
                var repeats=new ArrayList<Object>();
                for(int repeat=0;repeat<2;repeat++) {
                    long start=System.nanoTime();
                    var project=context.getBean(ProjectScanner.class).scan(directory);
                    var raw=context.getBean(VulnerabilityRuleEngine.class).execute(new RuleExecutionContext(project));
                    var filtered=context.getBean(FalsePositiveAnalyzer.class).analyze(project,raw);
                    var py=context.getBean(PythonServerAnalyzer.class).analyze(project);
                    var ts=context.getBean(TypeScriptServerAnalyzer.class).analyze(project);
                    var deploy=DeploymentAnalyzer.analyze(project,py.deploymentAnalysis());
                    var sca=context.getBean(ScaManifestCollector.class).collect(project);
                    var observed=new TreeSet<String>();
                    filtered.forEach(f->observed.add(f.ruleId()));
                    if(py.validatedFindings()!=null)py.validatedFindings().forEach(f->observed.add(f.ruleId()));
                    if(ts.validatedFindings()!=null)ts.validatedFindings().forEach(f->observed.add(f.ruleId()));
                    deploy.findings().forEach(f->observed.add(f.ruleId()));
                    var row=new LinkedHashMap<String,Object>();
                    row.put("detected",observed.contains(test.path("rule").asText()));row.put("ruleIds",observed);
                    row.put("rawRuleCount",raw.size());row.put("filteredRuleCount",filtered.size());
                    row.put("coverage",project.coverage());row.put("python",py);row.put("typescript",ts);row.put("deployment",deploy);
                    row.put("manifestObservations",sca.observations());row.put("dependencyComponents",sca.components());
                    row.put("elapsedMs",(System.nanoTime()-start)/1_000_000);repeats.add(row);
                }
                results.add(Map.of("id",id,"truth",test.path("truth").asText(),"area",test.path("area").asText(),
                        "support",test.path("support").asText(),"targetRule",test.path("rule").asText(),"runs",repeats));
                System.out.println("EVAL case="+id+" completed=2");
            }
        }
        mapper.writeValue(Path.of(args[1]).toFile(),Map.of("schemaVersion",1,"results",results));
    }
}
