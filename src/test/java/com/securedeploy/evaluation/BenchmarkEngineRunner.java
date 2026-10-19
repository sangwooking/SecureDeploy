package com.securedeploy.evaluation;

import com.fasterxml.jackson.databind.*;
import com.securedeploy.SecureDeployApplication;
import com.securedeploy.analysis.javaflow.JavaSqlAnalyzer;
import com.securedeploy.analysis.python.PythonServerAnalyzer;
import com.securedeploy.analysis.typescript.*;
import com.securedeploy.analysis.deployment.DeploymentAnalyzer;
import com.securedeploy.project.service.ProjectScanner;
import com.securedeploy.project.progress.ComparisonContextCollector;
import com.securedeploy.rule.engine.*;
import com.securedeploy.rule.filter.FalsePositiveAnalyzer;
import com.securedeploy.rule.model.RuleMatch;
import com.securedeploy.review.service.SecurityReviewService;
import com.securedeploy.risk.service.RiskPrioritizationEngine;
import com.securedeploy.sca.parser.ScaManifestCollector;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.lang.management.ManagementFactory;
import java.util.*;
import org.springframework.boot.builder.SpringApplicationBuilder;

/** Evaluation adapter only: real engine beans, isolated in-memory DB, no external clients called. */
public final class BenchmarkEngineRunner {
    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();
    public static void main(String[] args) throws Exception {
        if(!git("diff","HEAD","--name-only","--","src/main","analyzers").isBlank()
                ||!git("ls-files","--others","--exclude-standard","--","src/main","analyzers").isBlank())
            throw new IllegalStateException("COMMITTED_ENGINE_BASELINE_REQUIRED");
        Path root=Path.of(args[0]).toRealPath(), output=Path.of(args[1]).toAbsolutePath().normalize();
        if(Files.exists(output)||output.startsWith(Path.of(".").toRealPath())||Files.isSymbolicLink(output.getParent()))
            throw new IllegalArgumentException("OUTPUT_MUST_BE_NEW_OUTSIDE_REPOSITORY");
        Path manifest=root.resolve("manifest.json");
        if(Files.size(manifest)>2_000_000)throw new IllegalArgumentException("MANIFEST_LIMIT");
        var data=JSON.readTree(manifest.toFile());String split=args[2];
        if(!Set.of("REGRESSION","VALIDATION","HOLDOUT").contains(split))throw new IllegalArgumentException("INVALID_SPLIT");
        if(split.equals("HOLDOUT")&&!"YES".equals(System.getenv("BENCHMARK_RELEASE_HOLDOUT")))throw new IllegalArgumentException("HOLDOUT_RELEASE_REQUIRED");
        if(data.path("cases").size()>200||!data.path("cases").isArray())throw new IllegalArgumentException("CASE_LIMIT");
        var rows=new ArrayList<Object>();
        try(var context=new SpringApplicationBuilder(SecureDeployApplication.class).run(
                "--server.address=127.0.0.1","--server.port=0","--spring.datasource.url=jdbc:h2:mem:benchmark;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE",
                "--spring.datasource.username=sa","--spring.datasource.password=","--spring.datasource.driver-class-name=org.h2.Driver",
                "--spring.jpa.hibernate.ddl-auto=create-drop","--spring.sql.init.mode=never","--spring.flyway.enabled=false",
                "--securedeploy.jwt.secret=benchmark-synthetic-signing-key-not-production-0001",
                "--securedeploy.ai.provider=TEMPLATE","--securedeploy.github.app.enabled=false",
                "--securedeploy.sca.enabled=false","--securedeploy.threat-intelligence.enabled=false",
                "--logging.level.root=OFF","--spring.main.banner-mode=off")) {
            try(var connection=context.getBean(javax.sql.DataSource.class).getConnection()) {
                if(!connection.getMetaData().getURL().startsWith("jdbc:h2:mem:benchmark"))throw new IllegalStateException("ISOLATED_DB_REQUIRED");
            }
            for(var c:data.path("cases")) {
                String id=c.path("caseId").asText();
                if(!id.matches("[a-zA-Z0-9_-]{1,100}"))throw new IllegalArgumentException("CASE_ID");
                if(!split.equals(c.path("evaluationSplit").asText())||args.length>3&&!args[3].equals(id))continue;
                Path directory=root.resolve("cases").resolve(id).toRealPath();
                if(!directory.startsWith(root)||Files.isSymbolicLink(root.resolve("cases").resolve(id)))throw new IllegalArgumentException("CASE_PATH");
                verify(directory,c);
                var repeats=new ArrayList<Object>();
                for(int repeat=0;repeat<2;repeat++) {
                    long start=System.nanoTime();
                    var project=context.getBean(ProjectScanner.class).scan(directory);
                    var raw=context.getBean(VulnerabilityRuleEngine.class).execute(new RuleExecutionContext(project));
                    var java=context.getBean(JavaSqlAnalyzer.class).reconcile(raw,context.getBean(JavaSqlAnalyzer.class).analyze(project));
                    var filtered=context.getBean(FalsePositiveAnalyzer.class).analyze(project,java.matches());
                    var py=context.getBean(PythonServerAnalyzer.class).analyze(project);
                    var ts=context.getBean(TypeScriptServerAnalyzer.class).analyze(project);
                    var deployment=DeploymentAnalyzer.analyze(project,py.deploymentAnalysis());
                    var coverage=ts.attachCoverage(project.coverage());
                    coverage=py.attachCoverage(coverage);coverage=deployment.attachCoverage(coverage);
                    coverage=java.snapshot().attachCoverage(coverage);
                    coverage=coverage.withInspectionScope(com.securedeploy.project.coverage.InspectionScope.collect(coverage,project.analysisFiles()));
                    var response=context.getBean(SecurityReviewService.class).createResponse("benchmark",project.analysisFiles().size(),filtered);
                    // Null means lookup NOT RUN/UNKNOWN, never "zero vulnerable dependencies".
                    var risk=context.getBean(RiskPrioritizationEngine.class).assess(response.vulnerabilities(),null);
                    var sca=context.getBean(ScaManifestCollector.class).collect(project);
                    var candidates=new ArrayList<Object>();
                    for(var f:java.snapshot().findings())candidates.add(Map.of("ruleId",f.ruleId(),"location",f.location(),"trace",f.trace(),"priority",f.priority()));
                    addCandidates(candidates,py);addCandidates(candidates,ts);
                    for(var f:deployment.findings())candidates.add(Map.of("ruleId",f.ruleId(),"location",Map.of("filePath",f.filePath(),"line",f.line()),"trace",List.of(),"priority",f.priority()));
                    var row=new LinkedHashMap<String,Object>();
                    row.put("raw",signals(raw));row.put("reconciled",signals(java.matches()));row.put("filtered",signals(filtered));
                    row.put("reviewCandidates",candidates);row.put("java",java.snapshot());row.put("python",py);row.put("typescript",ts);
                    row.put("deployment",deployment);row.put("coverage",coverage);
                    row.put("filterAudit",filterAudit(java.matches(),filtered));
                    row.put("engineFingerprint",context.getBean(ComparisonContextCollector.class).collect(project).analyzerVersion());
                    row.put("risk",risk);row.put("securityScore",response.securityScore());
                    row.put("sca",Map.of("status","EXTERNAL_LOOKUP_NOT_RUN","componentCount",sca.components().size(),"observationCount",sca.observations().size()));
                    row.put("elapsedMs",(System.nanoTime()-start)/1_000_000);
                    row.put("parentHeapUsedBytes",ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed());
                    repeats.add(row);
                }
                rows.add(Map.of("caseId",id,"runs",repeats));
                System.out.println("BENCHMARK completed="+rows.size());
            }
        }
        if(rows.isEmpty())throw new IllegalArgumentException("NO_SELECTED_CASES");
        var result=Map.of("schemaVersion",1,"manifestSha256",hash(Files.readAllBytes(manifest)),
                "engineCommit",engineCommit(),"split",split,
                "runnerVersion",hash(BenchmarkEngineRunner.class.getResourceAsStream("BenchmarkEngineRunner.class").readAllBytes()),
                "isolation","IN_MEMORY_H2_NO_REVIEW_PERSISTENCE","externalLookups","NOT_RUN",
                "measurementLimits","Parent heap is a sample, not peak/RSS or child worker memory.",
                "selectionCaseId",args.length>3?args[3]:"ALL","results",rows);
        byte[] bytes=JSON.writerWithDefaultPrettyPrinter().writeValueAsBytes(result);
        Files.write(output,bytes,StandardOpenOption.CREATE_NEW);
    }
    static List<Object> signals(List<RuleMatch> matches) {
        return matches.stream().map(f->(Object)Map.of("ruleId",f.ruleId(),"filePath",f.filePath(),"line",f.line(),
                "severity",f.severity(),"confidence",f.confidence(),"falsePositiveRisk",f.falsePositiveRisk())).toList();
    }
    static void addCandidates(List<Object> out,ServerAnalysisSnapshot snapshot) {
        if(snapshot.validatedFindings()!=null)for(var f:snapshot.validatedFindings())
            out.add(Map.of("ruleId",f.ruleId(),"location",f.location(),"trace",f.evidence().stream().flatMap(e->e.flow().stream()).toList(),"priority",f.priority()));
    }
    static List<Object> filterAudit(List<RuleMatch> before,List<RuleMatch> after) {
        var out=new ArrayList<Object>();
        for(var f:before) {
            var retained=after.stream().filter(a->a.ruleId().equals(f.ruleId())&&a.filePath().equals(f.filePath())&&a.line()==f.line()).findFirst();
            if(retained.isEmpty())out.add(Map.of("ruleId",f.ruleId(),"filePath",f.filePath(),"line",f.line(),
                    "disposition","FPA_EXCLUDED","reasonAvailability","EXISTING_ANALYZER_DOES_NOT_RETURN_EXCLUSION_REASON"));
            else if(retained.get().confidence()!=f.confidence()||retained.get().falsePositiveRisk()!=f.falsePositiveRisk()||retained.get().severity()!=f.severity())
                out.add(Map.of("ruleId",f.ruleId(),"filePath",f.filePath(),"line",f.line(),"disposition","FPA_METADATA_ADJUSTED"));
        }
        return out;
    }
    static void verify(Path root,JsonNode c) throws Exception {
        var expected=new HashSet<Path>();long total=0;
        for(var f:c.path("files")) {
            String name=f.path("path").asText();Path file=root.resolve(name).normalize();
            if(!file.startsWith(root)||!Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS)||!file.toRealPath().startsWith(root))throw new IllegalArgumentException("SOURCE_PATH");
            long size=Files.size(file);total+=size;
            if(size>1_000_000||total>5_000_000||expected.size()>=40)throw new IllegalArgumentException("SOURCE_LIMIT");
            if(!hash(Files.readAllBytes(file)).equals(f.path("sha256").asText()))throw new IllegalArgumentException("SOURCE_HASH");
            expected.add(file);
        }
        try(var paths=Files.walk(root)) {
            var iterator=paths.iterator();int count=0;
            while(iterator.hasNext()) {
                var path=iterator.next();
                if(++count>500||Files.isSymbolicLink(path)||!Files.isDirectory(path)&&!expected.contains(path))
                    throw new IllegalArgumentException("UNEXPECTED_SOURCE_OR_SYMLINK");
            }
        }
    }
    static String hash(byte[] value) throws Exception {return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));}
    static String engineCommit() throws Exception {
        String sha=git("rev-parse","HEAD");
        if(!sha.matches("[0-9a-f]{40}"))throw new IllegalStateException("ENGINE_COMMIT_UNAVAILABLE");
        return sha;
    }
    static String git(String...args) throws Exception {
        var command=new ArrayList<String>();command.add("git");command.addAll(List.of(args));
        var process=new ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        if(!process.waitFor(5,java.util.concurrent.TimeUnit.SECONDS)){process.destroyForcibly();throw new IllegalStateException("ENGINE_COMMIT_UNAVAILABLE");}
        byte[] bytes=process.getInputStream().readNBytes(100001);
        if(process.exitValue()!=0||bytes.length>100000)throw new IllegalStateException("ENGINE_BASELINE_UNAVAILABLE");
        return new String(bytes,StandardCharsets.UTF_8).trim();
    }
}
