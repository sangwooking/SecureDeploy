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
        var selection=TypeScriptSourceSelector.select(project.analysisFiles());
        var result=analyzeInternal(project,selection).withSelectionCoverage(selection.coverage());
        if(result.supabaseAnalysis()!=null)return result;
        var sql=project.analysisFiles().stream().filter(f->f.type()==com.securedeploy.project.model.ProjectFileType.SUPABASE_SQL)
                .sorted(Comparator.comparing(f->f.relativePath())).limit(100)
                .map(f->new SupabaseSnapshot.SqlFile(CoverageRecorder.safePath(f.relativePath()),"NOT_RUN",0,List.of("ANALYZER_NOT_AVAILABLE"))).toList();
        return result.withSupabaseAnalysis(new SupabaseSnapshot(1,"supabase-rls-v4",sql.isEmpty()&&"NOT_APPLICABLE".equals(result.status())?"NOT_APPLICABLE":"PARTIAL",
                sql,List.of(),List.of(),List.of(),List.of(),List.of("DECLARATIONS_NOT_LIVE_DATABASE","ANALYZER_NOT_AVAILABLE")));
    }
    private ServerAnalysisSnapshot analyzeInternal(ProjectStructure project,TypeScriptSourceSelector.Plan selection) {
        var candidates = project.analysisFiles().stream().filter(f -> f.relativePath().matches(".*(?:\\.[jt]sx?|\\.[cm]js)$"))
                .sorted(Comparator.comparing(f -> f.relativePath())).toList();
        var sqlCandidates=project.analysisFiles().stream().filter(f->f.type()==com.securedeploy.project.model.ProjectFileType.SUPABASE_SQL)
                .sorted(Comparator.comparing(f->f.relativePath())).toList();
        List<Map<String, String>> sources = new ArrayList<>();
        List<FileCoverage> omitted = new ArrayList<>();
        Map<String, Integer> lineCounts = new HashMap<>();
        var selectionReasons=new HashMap<String,String>();
        for(var choice:selection.selected())if(!choice.sql()) {
            var file=choice.file();String path=CoverageRecorder.safePath(file.relativePath());
            sources.add(Map.of("filePath",path,"content",String.join("\n",file.lines())));
            lineCounts.put(path,file.lines().size());selectionReasons.put(path,choice.reason());
        }
        for(var choice:selection.omitted())if(!choice.sql()&&omitted.size()<MAX_FILES) {
            String path=CoverageRecorder.safePath(choice.file().relativePath());
            omitted.add(skipped(path,selection.omissions().get(choice.file().relativePath())).withSelectionReason(choice.reason()));
        }
        List<FileCoverage> unavailableFiles = new ArrayList<>(omitted);
        var policyFiles=new ArrayList<Map<String,String>>();var policyLines=new HashMap<String,Integer>();
        for(var choice:selection.selected())if(choice.sql()) {
            var file=choice.file();String path=CoverageRecorder.safePath(file.relativePath());
            policyFiles.add(Map.of("filePath",path,"status","SELECTED","content",String.join("\n",file.lines())));
            policyLines.put(path,file.lines().size());
        }
        for(var choice:selection.omitted())if(choice.sql()&&policyFiles.size()<100)
            policyFiles.add(Map.of("filePath",CoverageRecorder.safePath(choice.file().relativePath()),"status","LIMIT_EXCEEDED","reason",selection.omissions().get(choice.file().relativePath())));
        boolean policyInventoryComplete=sqlCandidates.size()<=100&&appendSourcePolicyOmissions(project,policyFiles);
        if(candidates.isEmpty()&&sqlCandidates.isEmpty()&&policyFiles.isEmpty())
            return ServerAnalysisSnapshot.unavailable(policyInventoryComplete?"NOT_APPLICABLE":"PARTIAL",List.of(),policyInventoryComplete?"NO_JAVASCRIPT_OR_TYPESCRIPT_FILES":"SOURCE_POLICY_INVENTORY_INCOMPLETE");
        sources.forEach(f -> unavailableFiles.add(new FileCoverage(f.get("filePath"), "NOT_RUN", "NOT_RUN", 0, 0, List.of()).withSelectionReason(selectionReasons.get(f.get("filePath")))));
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
            var manifests=NodeManifestMetadata.read(project.analysisFiles()).worker();
            var denoConfigs=new ArrayList<Map<String,Object>>();
            for(var file:project.analysisFiles().stream().sorted(Comparator.comparing(f->f.relativePath())).toList())if(file.relativePath().matches("(?:.*/)?supabase/config\\.toml") && denoConfigs.size()<20
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
            var ledger=project.coverage();
            var inventory=ledger==null?List.<String>of():java.util.stream.Stream.concat(ledger.entries().stream()
                    .map(e->e.filePath()),project.enumeratedDirectories().stream()).filter(p->!p.equals("."))
                    .map(CoverageRecorder::safePath).distinct().sorted().limit(1001).toList();
            boolean metadataComplete=ledger!=null&&ledger.omittedEntries()==0&&project.enumeratedDirectories().contains(".")
                    &&inventory.size()<=1000&&!inventory.contains("[redacted-path]");
            boolean inventoryComplete=metadataComplete&&ledger.inventoryComplete();
            byte[] input = mapper.writeValueAsBytes(Map.of("typescriptConfigs",TypeScriptConfigMetadata.read(project.analysisFiles()),"files", sources,"nodeManifests",manifests,"denoConfigs",denoConfigs,"policyFiles",policyFiles,"policyInventoryComplete",policyInventoryComplete,
                    "nodeSourceInventory",inventory.stream().limit(1000).toList(),"nodeSourceInventoryComplete",inventoryComplete,
                    "nodeEnumeratedDirectories",metadataComplete?project.enumeratedDirectories().stream().sorted().toList():List.of()));
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
            var files = new ArrayList<>(parsed.files().stream().map(f->f.withSelectionReason(selectionReasons.get(f.filePath()))).toList()); files.addAll(omitted);
            var limitations = new ArrayList<>(parsed.limitations());
            limitations.add("TS_SELECTION_HINTS_NOT_ENTRY_PROOF");
            if (!omitted.isEmpty()) limitations.add("SOURCE_LIMITS_OR_SENSITIVE_PATHS_OMITTED");
            if(!selection.hintsComplete())limitations.add("TS_SELECTION_HINT_LIMIT");
            if(selection.coverage().omittedFiles()>0)limitations.add("TS_COMBINED_SOURCE_SQL_BUDGET_PARTIAL");
            if (candidates.size() > sources.size() + omitted.size()) limitations.add("OMITTED_FILE_DETAILS_TRUNCATED");
            return new ServerAnalysisSnapshot(parsed.schemaVersion(), parsed.analyzerVersion(), parsed.parserVersion(),
                    selection.coverage().omittedFiles()==0 ? parsed.status() : "PARTIAL", List.copyOf(files), parsed.findings(), parsed.sqlUses(),
                    parsed.authorizationContexts(), List.copyOf(limitations), ServerFlowFinding.connect(parsed), parsed.httpUses()).withExposureUses(parsed.exposureUses()).withResourceUses(parsed.resourceUses()).withNodeUses(parsed.nodeUses()).withSupabaseAnalysis(parsed.supabaseAnalysis());
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

    // Source acquisition omissions are not selector omissions: their bytes never reached analysisFiles.
    private boolean appendSourcePolicyOmissions(ProjectStructure project,List<Map<String,String>> policies){
        boolean complete=policies.stream().noneMatch(p->"[redacted-path]".equals(p.get("filePath")));
        var ledger=project.coverage();if(ledger==null)return complete;
        complete&=ledger.omittedEntries()==0;
        var collector=new com.securedeploy.project.service.ProjectFileCollector();
        var seen=new HashSet<String>();policies.forEach(p->seen.add(p.get("filePath")));
        for(var e:ledger.entries().stream().sorted(Comparator.comparing(com.securedeploy.project.coverage.CoverageLedger.Entry::filePath)).toList()){
            if("SELECTED".equals(e.status()))continue;
            String path=CoverageRecorder.safePath(e.filePath());
            if("[redacted-path]".equals(path)){complete=false;continue;}
            Path relative=Path.of(path);
            if(com.securedeploy.project.service.ProjectIgnorePolicy.ignores(relative))continue;
            if("DIRECTORY".equals(e.kind())){
                if(path.matches("(?:.*/)?supabase(?:/(?:migrations|schemas|policies))?"))complete=false;
                continue;
            }
            if(!"FILE".equals(e.kind())||!("SUPABASE_SQL".equals(e.fileType())||collector.resolveAnalysisFileType(relative).filter(t->t==com.securedeploy.project.model.ProjectFileType.SUPABASE_SQL).isPresent())||seen.contains(path))continue;
            if(policies.size()>=100){complete=false;continue;}
            policies.add(Map.of("filePath",path,"status","NOT_RUN","reason","SOURCE_LEDGER_SQL_NOT_INSPECTED"));seen.add(path);
            // Non-migration sources have no unambiguous migration scope/order.
            if(!path.matches("(?:.*/)?supabase/migrations/[^/]+\\.sql"))complete=false;
        }
        return complete;
    }

    private void validateSupabase(SupabaseSnapshot snapshot,Map<String,Integer> files){
        if(snapshot==null)return; // Older fixture workers have no RLS snapshot.
        if(snapshot.schemaVersion()!=1||!"supabase-rls-v4".equals(snapshot.analyzerVersion())||snapshot.files().size()>100
                ||snapshot.tables().size()>200||snapshot.clients().size()>100||snapshot.accesses().size()>200||snapshot.findings().size()>200)throw new IllegalArgumentException("INVALID_RLS_RESPONSE");
        var locations=new ArrayList<ServerAnalysisSnapshot.Location>();
        snapshot.tables().forEach(t->{locations.add(t.location());locations.addAll(t.grantLocations());if(t.policies().size()>500||t.operations().size()>8)throw new IllegalArgumentException("INVALID_RLS_LIMIT");t.policies().forEach(p->locations.add(p.location()));});
        snapshot.tables().forEach(t->{
            if(t.updatePrivileges()==null)return;
            if(t.updatePrivileges().size()!=2)throw new IllegalArgumentException("INVALID_COLUMN_PRIVILEGES");
            var roles=new HashSet<String>();
            for(var p:t.updatePrivileges()){
                if(!roles.add(p.role())||!Set.of("anon","authenticated").contains(p.role())||!Set.of("DECLARATION_ONLY","UNKNOWN").contains(p.status())
                        ||!Set.of("EXPLICIT_GRANT","NOT_ESTABLISHED","UNKNOWN").contains(p.tableGrant())||p.columns().size()>128
                        ||p.columns().stream().anyMatch(c->c==null||c.length()>100)||new HashSet<>(p.columns()).size()!=p.columns().size()
                        ||"UNKNOWN".equals(p.status())&&(!"UNKNOWN".equals(p.tableGrant())||!p.columns().isEmpty()))throw new IllegalArgumentException("INVALID_COLUMN_PRIVILEGES");
            }
        });
        snapshot.clients().forEach(c->locations.add(c.location()));
        snapshot.accesses().forEach(a->{locations.add(a.location());if(a.clientLocation()!=null)locations.add(a.clientLocation());if(a.policyLocation()!=null)locations.add(a.policyLocation());});
        snapshot.accesses().forEach(a->{
            var w=a.writeEvidence();if(w==null)return;
            if(!Set.of("INSERT","UPDATE","DELETE").contains(a.operation())||!"CLIENT_DECLARATION_LINKED".equals(a.clientStatus())
                    ||a.authorizationEvidence()==null||a.authorizationEvidence().requestEntry()==null
                    ||!"LOCAL_VALUE_ORIGIN_EVIDENCE".equals(w.status())||!Set.of("STATIC_FIELDS","NO_PAYLOAD","UNKNOWN").contains(w.dataStatus())
                    ||!Set.of("STATIC_FILTERS","UNKNOWN").contains(w.filterStatus())||w.dataFields().size()>16||w.filters().size()>8||w.limitations().size()>12
                    ||!"STATIC_FIELDS".equals(w.dataStatus())&&!w.dataFields().isEmpty()
                    ||"DELETE".equals(a.operation())&&!"NO_PAYLOAD".equals(w.dataStatus()))throw new IllegalArgumentException("INVALID_WRITE_EVIDENCE");
            locations.add(w.operationLocation());
            var values=new ArrayList<>(w.dataFields());values.addAll(w.filters());
            values.forEach(v->{
                if(v.name()==null||!v.name().matches("[A-Za-z_][A-Za-z0-9_]{0,63}")||!Set.of("field","eq","match").contains(v.operator())
                        ||!Set.of("REQUEST_CONTROLLED","VERIFIED_USER_EVIDENCE","SESSION_UNVERIFIED","SERVER_CONTROLLED","UNKNOWN").contains(v.source())
                        ||v.sourceLocations().size()>4||v.limitations().size()>10)throw new IllegalArgumentException("INVALID_WRITE_VALUE");
                locations.add(v.location());locations.addAll(v.sourceLocations());
            });
            var c=w.columnUpdate();
            if(c!=null){
                if(!"UPDATE".equals(a.operation())||!"column-update-v1".equals(c.analyzerVersion())||!Set.of("DECLARATION_ONLY","UNKNOWN").contains(c.status())
                        ||c.roles().size()!=2||c.grantLocations().size()>8||c.limitations().size()>10)throw new IllegalArgumentException("INVALID_COLUMN_UPDATE");
                var roleNames=new HashSet<String>();
                for(var r:c.roles()){
                    if(!roleNames.add(r.role())||!Set.of("anon","authenticated").contains(r.role())||!Set.of("EXPLICIT_GRANT","NOT_ESTABLISHED","UNKNOWN").contains(r.tableGrant())
                            ||r.fields().size()!=w.dataFields().size())throw new IllegalArgumentException("INVALID_COLUMN_UPDATE");
                    for(int i=0;i<r.fields().size();i++){
                        var field=r.fields().get(i);var origin=w.dataFields().get(i);
                        if(!Objects.equals(field.name(),origin.name())||!Objects.equals(field.source(),origin.source())
                                ||!Set.of("TABLE_GRANT","COLUMN_GRANT","NOT_ESTABLISHED","UNKNOWN").contains(field.grant())
                                ||"UNKNOWN".equals(c.status())&&!"UNKNOWN".equals(field.grant()))throw new IllegalArgumentException("INVALID_COLUMN_FIELD");
                    }
                }
                locations.addAll(c.grantLocations());
            }
        });
        snapshot.accesses().forEach(a->{
            var e=a.authorizationEvidence();if(e==null)return;
            if(!Set.of("UNKNOWN","CONFIRMED_POLICY_EVIDENCE","BROAD_ACCESS_REVIEW","ADMIN_ACCESS_REVIEW","PUBLIC_READ_DECLARATION").contains(e.state())
                    ||!"UNKNOWN".equals(e.effectiveRole())||e.authChecks().size()>4||e.clientTrace().size()>8||e.policyLocations().size()>8
                    ||e.policyStates().size()>8||e.filterLocations().size()>4||e.limitations().size()>20)throw new IllegalArgumentException("INVALID_AUTHORIZATION_EVIDENCE");
            locations.addAll(e.clientTrace());locations.addAll(e.policyLocations());locations.addAll(e.filterLocations());
            if(e.enclosingFunction()!=null)locations.add(e.enclosingFunction());
            if(e.requestEntry()!=null){
                if(!Set.of("NEXT_ROUTE_HANDLER","NEXT_SERVER_FUNCTION").contains(e.requestEntry().kind()))throw new IllegalArgumentException("INVALID_REQUEST_CONTEXT");
                locations.add(e.requestEntry());
            }
            e.authChecks().forEach(c->{
                if(!Set.of("getUser","getClaims","getSession").contains(c.method()))throw new IllegalArgumentException("INVALID_AUTH_API");locations.add(c.location());
                var r=c.resultEvidence();if(r!=null){
                    if(!Set.of("getUser","getClaims").contains(c.method())||!"IDENTITY_RESULT_GUARD_OBSERVED".equals(r.status())||r.userIdFilters().size()>4||r.limitations().size()>10)throw new IllegalArgumentException("INVALID_AUTH_RESULT");
                    locations.add(r.guardLocation());locations.addAll(r.userIdFilters());
                }
            });
        });
        snapshot.findings().forEach(f->{if(!"REVIEW_REQUIRED".equals(f.priority())||!"NOT_COMPARED".equals(f.comparisonPolicy())||!"SUPABASE_BROAD_WRITE_DECLARATION".equals(f.ruleId()))throw new IllegalArgumentException("INVALID_RLS_FINDING");locations.add(f.location());locations.addAll(f.evidenceLocations());});
        if(snapshot.budgetUsage()!=null){
            var budget=snapshot.budgetUsage();
            var keys=Set.of("AST_NODES_INDEXED","STEPS_LIMIT","STEPS_USED","STEPS_SETUP","STEPS_POLICY","STEPS_CLIENT","STEPS_ENTRY_DISCOVERY","STEPS_FLOW","CLIENT_WORK_LIMIT","POLICY_WORK_LIMIT");
            if(!budget.keySet().equals(keys)||budget.values().stream().anyMatch(v->v==null||v<0||v>20_000_000)
                    ||budget.get("STEPS_LIMIT")>100_000||budget.get("STEPS_USED")>budget.get("STEPS_LIMIT")
                    ||budget.get("STEPS_USED")!=List.of("STEPS_SETUP","STEPS_POLICY","STEPS_CLIENT","STEPS_ENTRY_DISCOVERY","STEPS_FLOW").stream().mapToInt(budget::get).sum())
                throw new IllegalArgumentException("INVALID_BUDGET_USAGE");
        }
        for(var l:locations)if(l==null||!files.containsKey(l.filePath())||l.line()<1||l.line()>files.get(l.filePath()))throw new IllegalArgumentException("INVALID_RLS_LOCATION");
    }

    private void validate(ServerAnalysisSnapshot result, Map<String, Integer> files) {
        if (result.schemaVersion() != 1 || !"ts-server-v46".equals(result.analyzerVersion()) || !"6.0.3".equals(result.parserVersion())
                || result.files().size() != files.size() || result.findings().size() > 200 || result.sqlUses().size() > 200
                || result.httpUses() == null || result.httpUses().size() > 200
                || result.exposureUses() == null || result.exposureUses().size() > 200
                || result.nodeUses() == null || result.nodeUses().size() > 200
                || result.resourceUses() == null || result.resourceUses().size() > 200
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
            if(s.trace().size()>20||s.limitations().size()>20||!Set.of("JS_RATE_LIMIT_CONTEXT","JS_RATE_LIMIT_BYPASS_REVIEW","JS_WEB_SECURITY_CONTEXT","JS_CORS_CREDENTIAL_REFLECTION","JS_SESSION_COOKIE_ATTRIBUTE_REVIEW","JS_MONGOOSE_SELECTOR_INPUT_FLOW","JS_SEQUELIZE_SQL_INPUT_FLOW","JS_SHELL_COMMAND_INPUT_FLOW","JS_EVAL_INPUT_FLOW","JS_MONGO_WHERE_INPUT_FLOW","JS_MONGO_RESOURCE_ACCESS","JS_CONSTRUCTOR_EFFECT","JS_SERVER_ENTRY_CONTEXT").contains(s.ruleId()))throw new IllegalArgumentException("INVALID_NODE_USE");
            locations.add(s.location());locations.addAll(s.trace());
        });
        result.resourceUses().forEach(s->{
            if(!"JS_FILE_PATH_INPUT_FLOW".equals(s.ruleId())||!Set.of("STATIC_FILE_PATH","INPUT_IN_FILE_PATH","UNRESOLVED_RESOURCE").contains(s.kind())
                    ||s.trace().size()>20||s.defenses().size()>20||s.limitations().size()>20)throw new IllegalArgumentException("INVALID_FILE_RESOURCE_USE");
            locations.add(s.location());locations.addAll(s.trace());locations.addAll(s.defenses());
        });
        result.authorizationContexts().forEach(c -> { locations.add(c.entry()); locations.addAll(c.checks()); locations.addAll(c.defenses()); locations.addAll(c.resources()); });
        for (var location : locations) if (location == null || !files.containsKey(location.filePath()) || location.line() < 1
                || location.line() > files.get(location.filePath())) throw new IllegalArgumentException("INVALID_ANALYZER_LOCATION");
    }
}
