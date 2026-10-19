package com.securedeploy.evaluation;

import com.fasterxml.jackson.databind.*;
import com.securedeploy.SecureDeployApplication;
import com.securedeploy.project.service.ProjectScanner;
import com.securedeploy.project.coverage.*;
import com.securedeploy.analysis.javaflow.JavaSqlAnalyzer;
import com.securedeploy.analysis.python.PythonServerAnalyzer;
import com.securedeploy.analysis.typescript.TypeScriptServerAnalyzer;
import com.securedeploy.analysis.deployment.DeploymentAnalyzer;
import com.securedeploy.rule.engine.*;
import com.securedeploy.rule.filter.FalsePositiveAnalyzer;
import com.securedeploy.review.service.SecurityReviewService;
import com.securedeploy.risk.service.RiskPrioritizationEngine;
import com.securedeploy.sca.parser.ScaManifestCollector;
import com.securedeploy.project.progress.ComparisonContextCollector;
import java.nio.file.*;
import java.lang.management.ManagementFactory;
import java.util.*;
import org.springframework.boot.builder.SpringApplicationBuilder;

/** Whole retained application trees, not ground-truth SAFE cases or persisted user Reviews. */
public final class ApplicationEvaluationRunner {
    private static final ObjectMapper JSON=new ObjectMapper().findAndRegisterModules();
    public static void main(String[] args)throws Exception {
        if(!BenchmarkEngineRunner.git("diff","HEAD","--name-only","--","src/main","analyzers").isBlank()
                ||!BenchmarkEngineRunner.git("ls-files","--others","--exclude-standard","--","src/main","analyzers").isBlank())
            throw new IllegalStateException("COMMITTED_ENGINE_REQUIRED");
        Path root=Path.of(args[0]).toRealPath(),output=Path.of(args[1]).toAbsolutePath().normalize();
        if(Files.exists(output)||output.startsWith(Path.of(".").toRealPath())||Files.isSymbolicLink(output.getParent()))throw new IllegalArgumentException("NEW_EXTERNAL_OUTPUT_REQUIRED");
        Path plan=root.resolve("application-plan.json");
        if(Files.size(plan)>12_000_000)throw new IllegalArgumentException("PLAN_LIMIT");
        var data=JSON.readTree(plan.toFile());
        if(data.path("schemaVersion").asInt()!=1||data.path("projects").size()>8)throw new IllegalArgumentException("PROJECT_LIMIT");
        List<Object> projects=new ArrayList<>();
        try(var context=new SpringApplicationBuilder(SecureDeployApplication.class).run(
                "--server.address=127.0.0.1","--server.port=0","--spring.datasource.url=jdbc:h2:mem:application_eval;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE",
                "--spring.datasource.username=sa","--spring.datasource.password=","--spring.datasource.driver-class-name=org.h2.Driver",
                "--spring.jpa.hibernate.ddl-auto=create-drop","--spring.sql.init.mode=never","--spring.flyway.enabled=false",
                "--securedeploy.jwt.secret=application-evaluation-synthetic-key-not-production-0001",
                "--securedeploy.ai.provider=TEMPLATE","--securedeploy.github.app.enabled=false",
                "--securedeploy.sca.enabled=false","--securedeploy.threat-intelligence.enabled=false",
                "--logging.level.root=OFF","--spring.main.banner-mode=off")) {
            try(var connection=context.getBean(javax.sql.DataSource.class).getConnection()) {
                if(!connection.getMetaData().getURL().startsWith("jdbc:h2:mem:application_eval"))throw new IllegalStateException("ISOLATED_DB_REQUIRED");
            }
            for(var p:data.path("projects")) {
                String id=p.path("projectId").asText();
                if(!id.matches("[A-Za-z0-9_.-]{1,150}"))throw new IllegalArgumentException("PROJECT_ID");
                if(args.length>2&&!args[2].equals(id))continue;
                var entry=new LinkedHashMap<String,Object>();entry.put("projectId",id);entry.put("commitSha",p.path("commitSha").asText());
                if(!p.path("collectionStatus").asText().startsWith("COLLECTED")) {
                    entry.put("status","COLLECTION_FAILED_NOT_ANALYZED");projects.add(entry);continue;
                }
                List<Object> runs=new ArrayList<>();
                try {
                    Path source=root.resolve("sources").resolve(id).toRealPath();
                    verify(root,source,p);
                    for(int repeat=0;repeat<2;repeat++) {
                        long start=System.nanoTime();
                        var omitted=new CoverageRecorder();
                        for(var f:p.path("omitted"))omitted.record(f.path("filePath").asText(),"FILE",null,f.path("status").asText(),f.path("reason").asText());
                        var project=context.getBean(ProjectScanner.class).scan(source,omitted.snapshot());
                        var raw=context.getBean(VulnerabilityRuleEngine.class).execute(new RuleExecutionContext(project));
                        var java=context.getBean(JavaSqlAnalyzer.class).reconcile(raw,context.getBean(JavaSqlAnalyzer.class).analyze(project));
                        var filtered=context.getBean(FalsePositiveAnalyzer.class).analyze(project,java.matches());
                        var py=context.getBean(PythonServerAnalyzer.class).analyze(project);
                        var ts=context.getBean(TypeScriptServerAnalyzer.class).analyze(project);
                        var deployment=DeploymentAnalyzer.analyze(project,py.deploymentAnalysis());
                        var coverage=java.snapshot().attachCoverage(deployment.attachCoverage(py.attachCoverage(ts.attachCoverage(project.coverage()))));
                        coverage=coverage.withInspectionScope(InspectionScope.collect(coverage,project.analysisFiles()));
                        var response=context.getBean(SecurityReviewService.class).createResponse("application-evaluation",project.analysisFiles().size(),filtered);
                        var risk=context.getBean(RiskPrioritizationEngine.class).assess(response.vulnerabilities(),null);
                        var sca=context.getBean(ScaManifestCollector.class).collect(project);
                        var candidates=new ArrayList<Object>();
                        for(var f:java.snapshot().findings())candidates.add(Map.of("ruleId",f.ruleId(),"location",f.location(),"trace",f.trace(),"priority",f.priority()));
                        BenchmarkEngineRunner.addCandidates(candidates,py);BenchmarkEngineRunner.addCandidates(candidates,ts);
                        for(var f:deployment.findings())candidates.add(Map.of("ruleId",f.ruleId(),"location",Map.of("filePath",f.filePath(),"line",f.line()),"trace",List.of(),"priority",f.priority()));
                        var row=new LinkedHashMap<String,Object>();
                        row.put("raw",BenchmarkEngineRunner.signals(raw));row.put("filtered",BenchmarkEngineRunner.signals(filtered));
                        row.put("reviewCandidates",candidates);row.put("filterAudit",BenchmarkEngineRunner.filterAudit(java.matches(),filtered));
                        row.put("java",java.snapshot());row.put("python",py);row.put("typescript",ts);row.put("deployment",deployment);row.put("coverage",coverage);
                        row.put("sca",Map.of("status","EXTERNAL_LOOKUP_NOT_RUN","componentCount",sca.components().size(),"observationCount",sca.observations().size()));
                        row.put("risk",risk);row.put("securityScore",response.securityScore());
                        row.put("engineFingerprint",context.getBean(ComparisonContextCollector.class).collect(project).analyzerVersion());
                        row.put("elapsedMs",(System.nanoTime()-start)/1_000_000);row.put("parentHeapUsedBytes",ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed());
                        runs.add(row);
                    }
                    entry.put("status","ANALYZED_WITH_SCOPE_LIMITS_NOT_SAFETY_CERTIFICATION");entry.put("runs",runs);
                }catch(Exception error) {
                    entry.put("status","ANALYSIS_FAILED");entry.put("errorCategory",error.getClass().getSimpleName());
                    if(error instanceof CoverageException failure)entry.put("failureCoverage",failure.coverage());
                }
                projects.add(entry);System.out.println("APPLICATION completed="+projects.size());
            }
        }
        if(projects.isEmpty())throw new IllegalArgumentException("NO_SELECTED_PROJECT");
        var result=Map.of("schemaVersion",1,"engineCommit",BenchmarkEngineRunner.engineCommit(),"planSha256",BenchmarkEngineRunner.hash(Files.readAllBytes(plan)),
                "track","REAL_WORLD_WEB_APPLICATION","externalLookups","NOT_RUN","userDatabase","NOT_USED","projects",projects);
        Files.write(output,JSON.writerWithDefaultPrettyPrinter().writeValueAsBytes(result),StandardOpenOption.CREATE_NEW);
        if(Files.getFileStore(output).supportsFileAttributeView("posix"))
            Files.setPosixFilePermissions(output,java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
    }

    static void verify(Path root,Path source,JsonNode project)throws Exception {
        if(!source.startsWith(root)||Files.isSymbolicLink(source)||project.path("files").size()>20000)throw new IllegalArgumentException("SOURCE_IDENTITY");
        Set<Path> expected=new HashSet<>();long total=0;
        for(var f:project.path("files")) {
            Path path=source.resolve(f.path("path").asText()).normalize();
            if(!path.startsWith(source)||!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)||!path.toRealPath().startsWith(source))throw new IllegalArgumentException("SOURCE_PATH");
            long size=Files.size(path);total+=size;
            if(size>4_000_000||total>128_000_000||!expected.add(path)||!BenchmarkEngineRunner.hash(Files.readAllBytes(path)).equals(f.path("sha256").asText()))throw new IllegalArgumentException("SOURCE_HASH_OR_LIMIT");
        }
        try(var paths=Files.walk(source)) {
            var iterator=paths.iterator();int count=0;
            while(iterator.hasNext()) {
                var path=iterator.next();
                if(++count>50000||Files.isSymbolicLink(path)||!Files.isDirectory(path)&&!expected.contains(path))throw new IllegalArgumentException("UNEXPECTED_SOURCE");
            }
        }
    }
}
