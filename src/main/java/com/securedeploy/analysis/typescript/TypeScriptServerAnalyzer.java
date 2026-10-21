package com.securedeploy.analysis.typescript;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.project.model.ProjectStructure;
import com.securedeploy.project.coverage.CoverageRecorder;
import com.securedeploy.analysis.typescript.ServerAnalysisSnapshot.FileCoverage;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import org.springframework.stereotype.Service;

@Service
public class TypeScriptServerAnalyzer {
    private static final int MAX_FILES = 100, MAX_FILE_CHARS = 100_000, MAX_TOTAL_CHARS = 1_000_000;
    private static final int MAX_OUTPUT_BYTES = 2_000_000;
    private final Semaphore capacity = new Semaphore(2);
    private final TypeScriptAnalysisProperties properties;
    private final ObjectMapper mapper = new ObjectMapper();
    public TypeScriptServerAnalyzer(TypeScriptAnalysisProperties properties) { this.properties = properties; }

    public ServerAnalysisSnapshot analyze(ProjectStructure project) {
        var result=analyzeInternal(project);
        if(result.supabaseAnalysis()!=null)return result;
        var sql=project.analysisFiles().stream().filter(f->f.type()==com.securedeploy.project.model.ProjectFileType.SUPABASE_SQL).limit(100)
                .map(f->new SupabaseSnapshot.SqlFile(CoverageRecorder.safePath(f.relativePath()),"NOT_RUN",0,List.of("ANALYZER_NOT_AVAILABLE"))).toList();
        return result.withSupabaseAnalysis(new SupabaseSnapshot(1,"supabase-rls-v1",sql.isEmpty()&&"NOT_APPLICABLE".equals(result.status())?"NOT_APPLICABLE":"PARTIAL",
                sql,List.of(),List.of(),List.of(),List.of(),List.of("DECLARATIONS_NOT_LIVE_DATABASE","ANALYZER_NOT_AVAILABLE")));
    }
    private ServerAnalysisSnapshot analyzeInternal(ProjectStructure project) {
        var candidates = project.analysisFiles().stream().filter(f -> f.relativePath().matches(".*(?:\\.[jt]sx?|\\.[cm]js)$"))
                .sorted(Comparator.comparing(f -> f.relativePath())).toList();
        var sqlCandidates=project.analysisFiles().stream().filter(f->f.type()==com.securedeploy.project.model.ProjectFileType.SUPABASE_SQL)
                .sorted(Comparator.comparing(f->f.relativePath())).toList();
        if (candidates.isEmpty()&&sqlCandidates.isEmpty()) return ServerAnalysisSnapshot.unavailable("NOT_APPLICABLE", List.of(), "NO_JAVASCRIPT_OR_TYPESCRIPT_FILES");
        List<Map<String, String>> sources = new ArrayList<>();
        List<FileCoverage> omitted = new ArrayList<>();
        Map<String, Integer> lineCounts = new HashMap<>();
        int total = 0;
        for (var file : candidates) {
            String path = CoverageRecorder.safePath(file.relativePath());
            long length = file.lines().stream().mapToLong(line -> line.length() + 1L).sum();
            if (path.equals("[redacted-path]")) {
                if (omitted.size() < MAX_FILES) omitted.add(skipped(path, "SENSITIVE_PATH_OMITTED"));
            } else if (sources.size() >= MAX_FILES || length > MAX_FILE_CHARS || length + total > MAX_TOTAL_CHARS) {
                if (omitted.size() < MAX_FILES) omitted.add(skipped(path, "SOURCE_LIMIT_EXCEEDED"));
            } else {
                sources.add(Map.of("filePath", path, "content", String.join("\n", file.lines())));
                lineCounts.put(path, file.lines().size()); total += (int) length;
            }
        }
        List<FileCoverage> unavailableFiles = new ArrayList<>(omitted);
        var policyFiles=new ArrayList<Map<String,String>>();var policyLines=new HashMap<String,Integer>();
        for(var file:sqlCandidates){
            if(policyFiles.size()>=100)break;
            String path=CoverageRecorder.safePath(file.relativePath());
            long size=file.lines().stream().mapToLong(s->s.length()+1L).sum();
            if(!path.equals("[redacted-path]")&&size<=MAX_FILE_CHARS&&total+size<=MAX_TOTAL_CHARS&&sources.size()+policyLines.size()<MAX_FILES){
                policyFiles.add(Map.of("filePath",path,"status","SELECTED","content",String.join("\n",file.lines())));
                policyLines.put(path,file.lines().size());total+=(int)size;
            }else policyFiles.add(Map.of("filePath",path,"status","LIMIT_EXCEEDED"));
        }
        sources.forEach(f -> unavailableFiles.add(new FileCoverage(f.get("filePath"), "NOT_RUN", "NOT_RUN", 0, 0, List.of())));
        if (!properties.isEnabled()) return ServerAnalysisSnapshot.unavailable("DISABLED", unavailableFiles, "ANALYZER_DISABLED");
        if (sources.isEmpty()&&policyFiles.isEmpty()) return ServerAnalysisSnapshot.unavailable("PARTIAL", unavailableFiles, "NO_SOURCE_WITHIN_LIMITS");
        if (!capacity.tryAcquire()) return ServerAnalysisSnapshot.unavailable("UNAVAILABLE", unavailableFiles, "ANALYZER_CAPACITY_LIMIT");
        Process process = null;
        ExecutorService io = Executors.newFixedThreadPool(2, r -> { var thread = new Thread(r, "typescript-analysis-io"); thread.setDaemon(true); return thread; });
        try {
            Path directory = Path.of(properties.getAnalyzerDirectory()).toRealPath();
            if (!Files.isRegularFile(directory.resolve("worker.mjs"))
                    || !Files.isRegularFile(directory.resolve("node_modules/typescript/lib/typescript.js")))
                return ServerAnalysisSnapshot.unavailable("UNAVAILABLE", unavailableFiles, "TRUSTED_PARSER_NOT_INSTALLED");
            var manifests=new ArrayList<Map<String,String>>();
            for(var file:project.analysisFiles())if(file.relativePath().endsWith("package.json")&&manifests.size()<100
                    &&file.lines().stream().mapToLong(String::length).sum()<100_000) {
                try {
                    var document=mapper.readTree(String.join("\n",file.lines()));var manifest=new HashMap<String,String>();
                    String path=CoverageRecorder.safePath(file.relativePath());if(path.equals("[redacted-path]"))continue;
                    manifest.put("filePath",path);
                    for(String name:List.of("express","mongodb")) {
                        String version=document.path("dependencies").path(name).asText("");
                        if(version.length()<=80&&version.matches("[~^]?[0-9]+\\.[0-9]+\\.[0-9]+(?:-[A-Za-z0-9.-]+)?"))manifest.put(name,version);
                    }
                    manifests.add(manifest);
                }catch(Exception ignored){/* A malformed manifest cannot establish a driver API contract. */}
            }
            var denoConfigs=new ArrayList<Map<String,Object>>();
            for(var file:project.analysisFiles())if(file.relativePath().matches("(?:.*/)?supabase/config\\.toml") && denoConfigs.size()<20
                    &&file.lines().stream().mapToLong(String::length).sum()<100_000) {
                String path=CoverageRecorder.safePath(file.relativePath());
                if(path.equals("[redacted-path]"))continue;
                var settings=new TreeMap<String,Boolean>();String status="UNKNOWN";
                try {
                    var parsed=org.tomlj.Toml.parse(String.join("\n",file.lines()));
                    if(!parsed.hasErrors()) {
                        status="PARSED";var functions=parsed.getTable("functions");
                        if(functions!=null)for(String name:functions.keySet().stream().sorted().limit(100).toList()) {
                            if(!name.matches("[A-Za-z0-9_-]{1,100}"))continue;
                            var function=functions.getTable(List.of(name));
                            if(function!=null && function.get("verify_jwt") instanceof Boolean flag)settings.put(name,flag);
                        }
                    }
                }catch(Exception ignored){/* Configuration errors never establish runtime authorization. */}
                denoConfigs.add(Map.of("filePath",path,"status",status,"verifyJwt",settings));
            }
            byte[] input = mapper.writeValueAsBytes(Map.of("files", sources,"nodeManifests",manifests,"denoConfigs",denoConfigs,"policyFiles",policyFiles,"policyInventoryComplete",sqlCandidates.size()<=100));
            var builder = new ProcessBuilder(properties.getNodeExecutable(), "--permission", "--no-addons",
                    "--max-old-space-size=192", "--allow-fs-read=" + directory,
                    directory.resolve("worker.mjs").toString());
            builder.directory(directory.toFile());
            // Do not inherit JWT/DB/GitHub/OpenAI keys, NODE_OPTIONS, preloaders or target module paths.
            builder.environment().clear(); builder.environment().put("LANG", "en_US.UTF-8");
            builder.redirectError(ProcessBuilder.Redirect.DISCARD);
            process = builder.start();
            Process child = process;
            Future<?> writer = io.submit(() -> { try (var output = child.getOutputStream()) { output.write(input); }
                catch (java.io.IOException failure) { throw new IllegalStateException("ANALYZER_INPUT_FAILED"); } });
            Future<byte[]> reader = io.submit(() -> { try (var output = child.getInputStream()) { return output.readNBytes(MAX_OUTPUT_BYTES + 1); } });
            if (!process.waitFor(properties.getTimeoutSeconds(), TimeUnit.SECONDS))
                return ServerAnalysisSnapshot.unavailable("TIMEOUT", unavailableFiles, "ANALYZER_TIMEOUT");
            writer.get(1, TimeUnit.SECONDS);
            byte[] output = reader.get(1, TimeUnit.SECONDS);
            if (process.exitValue() != 0 || output.length > MAX_OUTPUT_BYTES)
                return ServerAnalysisSnapshot.unavailable("UNAVAILABLE", unavailableFiles, "PARSER_PROCESS_FAILED");
            var parsed = mapper.readValue(output, ServerAnalysisSnapshot.class);
            validate(parsed, lineCounts);
            var rlsLines=new HashMap<>(lineCounts);rlsLines.putAll(policyLines);validateSupabase(parsed.supabaseAnalysis(),rlsLines);
            var files = new ArrayList<>(parsed.files()); files.addAll(omitted);
            var limitations = new ArrayList<>(parsed.limitations());
            if (!omitted.isEmpty()) limitations.add("SOURCE_LIMITS_OR_SENSITIVE_PATHS_OMITTED");
            if (candidates.size() > sources.size() + omitted.size()) limitations.add("OMITTED_FILE_DETAILS_TRUNCATED");
            return new ServerAnalysisSnapshot(parsed.schemaVersion(), parsed.analyzerVersion(), parsed.parserVersion(),
                    omitted.isEmpty() ? parsed.status() : "PARTIAL", List.copyOf(files), parsed.findings(), parsed.sqlUses(),
                    parsed.authorizationContexts(), List.copyOf(limitations), ServerFlowFinding.connect(parsed), parsed.httpUses()).withExposureUses(parsed.exposureUses()).withNodeUses(parsed.nodeUses()).withSupabaseAnalysis(parsed.supabaseAnalysis());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return ServerAnalysisSnapshot.unavailable("UNAVAILABLE", unavailableFiles, "ANALYSIS_INTERRUPTED");
        } catch (Exception failure) {
            // Never expose source, child stderr or process environment in an API error or log.
            return ServerAnalysisSnapshot.unavailable("UNAVAILABLE", unavailableFiles, "PARSER_PROCESS_OR_RESPONSE_FAILED");
        } finally {
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
                try { process.waitFor(2, TimeUnit.SECONDS); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
            }
            io.shutdownNow(); capacity.release();
        }
    }

    private FileCoverage skipped(String path, String reason) {
        return new FileCoverage(path, "LIMIT_EXCEEDED", "NOT_RUN", 0, 0, List.of(reason));
    }

    private void validateSupabase(SupabaseSnapshot snapshot,Map<String,Integer> files){
        if(snapshot==null)return; // Older fixture workers have no RLS snapshot.
        if(snapshot.schemaVersion()!=1||!"supabase-rls-v1".equals(snapshot.analyzerVersion())||snapshot.files().size()>100
                ||snapshot.tables().size()>200||snapshot.clients().size()>100||snapshot.accesses().size()>200||snapshot.findings().size()>200)throw new IllegalArgumentException("INVALID_RLS_RESPONSE");
        var locations=new ArrayList<ServerAnalysisSnapshot.Location>();
        snapshot.tables().forEach(t->{locations.add(t.location());locations.addAll(t.grantLocations());if(t.policies().size()>500||t.operations().size()>8)throw new IllegalArgumentException("INVALID_RLS_LIMIT");t.policies().forEach(p->locations.add(p.location()));});
        snapshot.clients().forEach(c->locations.add(c.location()));
        snapshot.accesses().forEach(a->{locations.add(a.location());if(a.clientLocation()!=null)locations.add(a.clientLocation());if(a.policyLocation()!=null)locations.add(a.policyLocation());});
        snapshot.findings().forEach(f->{if(!"REVIEW_REQUIRED".equals(f.priority())||!"NOT_COMPARED".equals(f.comparisonPolicy())||!"SUPABASE_BROAD_WRITE_DECLARATION".equals(f.ruleId()))throw new IllegalArgumentException("INVALID_RLS_FINDING");locations.add(f.location());locations.addAll(f.evidenceLocations());});
        for(var l:locations)if(l==null||!files.containsKey(l.filePath())||l.line()<1||l.line()>files.get(l.filePath()))throw new IllegalArgumentException("INVALID_RLS_LOCATION");
    }

    private void validate(ServerAnalysisSnapshot result, Map<String, Integer> files) {
        if (result.schemaVersion() != 1 || !"ts-server-v12".equals(result.analyzerVersion()) || !"6.0.3".equals(result.parserVersion())
                || result.files().size() != files.size() || result.findings().size() > 200 || result.sqlUses().size() > 200
                || result.httpUses() == null || result.httpUses().size() > 200
                || result.exposureUses() == null || result.exposureUses().size() > 200
                || result.nodeUses() == null || result.nodeUses().size() > 200
                || result.authorizationContexts().size() > 200) throw new IllegalArgumentException("INVALID_ANALYZER_RESPONSE");
        if (!result.files().stream().map(FileCoverage::filePath).collect(java.util.stream.Collectors.toSet()).equals(files.keySet()))
            throw new IllegalArgumentException("INVALID_ANALYZER_FILES");
        var locations = new ArrayList<ServerAnalysisSnapshot.Location>();
        result.findings().forEach(f -> { locations.add(f.source()); locations.add(f.sink()); locations.addAll(f.flow()); locations.addAll(f.defenses()); });
        result.sqlUses().forEach(s -> { locations.add(s.location()); locations.addAll(s.trace()); locations.addAll(s.defenses());
            if (s.executionLocations() != null) locations.addAll(s.executionLocations()); });
        result.httpUses().forEach(s -> { locations.add(s.location()); locations.addAll(s.trace()); locations.addAll(s.defenses()); });
        result.exposureUses().forEach(s -> {
            if (s.trace().size() > 20 || s.limitations().size() > 20) throw new IllegalArgumentException("INVALID_EXPOSURE_LIMIT");
            locations.add(s.location()); locations.addAll(s.trace());
        });
        result.nodeUses().forEach(s->{
            if(s.trace().size()>20||s.limitations().size()>20||!Set.of("JS_EVAL_INPUT_FLOW","JS_MONGO_WHERE_INPUT_FLOW","JS_MONGO_RESOURCE_ACCESS","JS_CONSTRUCTOR_EFFECT","JS_SERVER_ENTRY_CONTEXT").contains(s.ruleId()))throw new IllegalArgumentException("INVALID_NODE_USE");
            locations.add(s.location());locations.addAll(s.trace());
        });
        result.authorizationContexts().forEach(c -> { locations.add(c.entry()); locations.addAll(c.checks()); locations.addAll(c.defenses()); locations.addAll(c.resources()); });
        for (var location : locations) if (location == null || !files.containsKey(location.filePath()) || location.line() < 1
                || location.line() > files.get(location.filePath())) throw new IllegalArgumentException("INVALID_ANALYZER_LOCATION");
    }
}
