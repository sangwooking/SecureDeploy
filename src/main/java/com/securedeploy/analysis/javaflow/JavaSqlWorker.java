package com.securedeploy.analysis.javaflow;

import com.sun.source.tree.*;
import com.sun.source.util.*;
import javax.tools.*;
import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Trusted JDK-only worker. Target text is parsed, never attributed, compiled or loaded. */
public final class JavaSqlWorker {
    public static final String VERSION = "java-sql-v2";
    public record Source(String path, String content) { }
    public record Location(String filePath, int line, int column, String functionName, String kind) { }
    public record FileResult(String filePath, String parseStatus, int entrypoints, int functions,
                             int sqlCallSites, int tracedCallSites, List<String> limitations) { }
    public record MethodResult(String filePath, int startLine, int endLine, boolean safeForLegacy) { }
    public record Use(String kind, String api, Location location, List<Location> trace,
                      int bindingCalls, List<String> limitations) { }
    public record Result(String version, String status, List<FileResult> files, List<MethodResult> methods,
                         List<Use> uses, List<String> limitations) { }

    public static void main(String[] args) throws Exception {
        try (var input = new DataInputStream(System.in); var output = new DataOutputStream(System.out)) {
            int count = bounded(input.readInt(), 100), chars = 0;
            var sources = new ArrayList<Source>();
            for (int i = 0; i < count; i++) {
                String path = input.readUTF();
                int size = bounded(input.readInt(), 400_000);
                byte[] bytes = input.readNBytes(size);
                if (bytes.length != size || path.length() > 1024) throw new IOException("INVALID_INPUT");
                String content = new String(bytes, StandardCharsets.UTF_8);
                chars += content.length();
                if (content.length() > 100_000 || chars > 1_000_000) throw new IOException("INPUT_LIMIT");
                sources.add(new Source(path, content));
            }
            write(output, new Engine(sources).run());
        }
    }

    public static void write(DataOutputStream out, Result r) throws IOException {
        out.writeUTF(r.version()); out.writeUTF(r.status()); out.writeInt(r.files().size());
        for (var f : r.files()) {
            out.writeUTF(f.filePath()); out.writeUTF(f.parseStatus()); out.writeInt(f.entrypoints());
            out.writeInt(f.functions()); out.writeInt(f.sqlCallSites()); out.writeInt(f.tracedCallSites()); strings(out, f.limitations());
        }
        out.writeInt(r.methods().size());
        for (var m : r.methods()) { out.writeUTF(m.filePath()); out.writeInt(m.startLine()); out.writeInt(m.endLine()); out.writeBoolean(m.safeForLegacy()); }
        out.writeInt(r.uses().size());
        for (var u : r.uses()) {
            out.writeUTF(u.kind()); out.writeUTF(u.api()); location(out, u.location()); out.writeInt(u.trace().size());
            for (var l : u.trace()) location(out, l);
            out.writeInt(u.bindingCalls()); strings(out, u.limitations());
        }
        strings(out, r.limitations());
    }
    public static Result read(DataInputStream in) throws IOException {
        String version = in.readUTF(), status = in.readUTF();
        var files = new ArrayList<FileResult>();
        for (int i = 0, n = bounded(in.readInt(), 200); i < n; i++)
            files.add(new FileResult(in.readUTF(), in.readUTF(), bounded(in.readInt(), 1000), bounded(in.readInt(), 3000),
                    bounded(in.readInt(), 30000), bounded(in.readInt(), 30000), strings(in)));
        var methods = new ArrayList<MethodResult>();
        for (int i = 0, n = bounded(in.readInt(), 1000); i < n; i++)
            methods.add(new MethodResult(in.readUTF(), in.readInt(), in.readInt(), in.readBoolean()));
        var uses = new ArrayList<Use>();
        for (int i = 0, n = bounded(in.readInt(), 200); i < n; i++) {
            String kind = in.readUTF(), api = in.readUTF(); Location l = location(in);
            var trace = new ArrayList<Location>();
            for (int j = 0, k = bounded(in.readInt(), 20); j < k; j++) trace.add(location(in));
            uses.add(new Use(kind, api, l, trace, bounded(in.readInt(), 10000), strings(in)));
        }
        return new Result(version, status, files, methods, uses, strings(in));
    }
    private static void location(DataOutputStream out, Location l) throws IOException {
        out.writeUTF(l.filePath()); out.writeInt(l.line()); out.writeInt(l.column()); out.writeUTF(l.functionName()); out.writeUTF(l.kind());
    }
    private static Location location(DataInputStream in) throws IOException { return new Location(in.readUTF(), in.readInt(), in.readInt(), in.readUTF(), in.readUTF()); }
    private static void strings(DataOutputStream out, List<String> items) throws IOException { out.writeInt(items.size()); for (String s : items) out.writeUTF(s); }
    private static List<String> strings(DataInputStream in) throws IOException {
        var items = new ArrayList<String>();
        for (int i = 0, n = bounded(in.readInt(), 50); i < n; i++) { String s = in.readUTF(); if (s.length() > 256) throw new IOException("METADATA_LIMIT"); items.add(s); }
        return List.copyOf(items);
    }
    private static int bounded(int n, int max) throws IOException { if (n < 0 || n > max) throw new IOException("PROTOCOL_LIMIT"); return n; }

    private record Unit(Source source, CompilationUnitTree tree, SourcePositions positions,
                        Map<String,String> imports, Set<String> localTypes) { }
    private record Method(Unit unit, ClassTree owner, MethodTree tree, Map<String,String> fields) { }
    private record Val(String type, Object constant, boolean input, boolean unknown, List<Location> trace, Val sql) {
        static Val literal(Object value) { return new Val("VALUE", value, false, false, List.of(), null); }
        static Val unknownValue() { return new Val("VALUE", null, false, true, List.of(), null); }
        static Val object(String type) { return new Val(type, null, false, false, List.of(), null); }
        Val step(Location l) {
            var t = new ArrayList<>(trace); if (t.size() < 20 && !t.contains(l)) t.add(l);
            return new Val(type, constant, input, unknown || trace.size() >= 20, List.copyOf(t), sql);
        }
        Val uncertain() { return new Val(type, null, input, true, trace, sql); }
    }
    private static final class Env {
        final Map<String,Val> values = new LinkedHashMap<>();
        final Map<String,String> types = new HashMap<>();
        final Map<String,Integer> bindings = new HashMap<>();
        final Map<String,Val> batches = new HashMap<>();
        boolean guardUnknown, partial;
        Env copy() { var e = new Env(); e.values.putAll(values); e.types.putAll(types); e.bindings.putAll(bindings);e.batches.putAll(batches); e.guardUnknown=guardUnknown; e.partial=partial; return e; }
        void take(Env e) { values.clear(); values.putAll(e.values); types.clear(); types.putAll(e.types); bindings.clear();bindings.putAll(e.bindings);batches.clear();batches.putAll(e.batches);guardUnknown=e.guardUnknown; partial=e.partial; }
    }
    private record Flow(boolean stopped, Val value) { static Flow next() { return new Flow(false, Val.unknownValue()); } }
    private static final class Budget extends RuntimeException { }

    private static final class Engine {
        final List<Source> sources;
        final List<FileResult> files = new ArrayList<>();
        final List<Method> methods = new ArrayList<>();
        final Map<Method, List<Use>> executions = new LinkedHashMap<>();
        final Map<Method, Boolean> complete = new HashMap<>();
        final LinkedHashMap<String,Use> uses = new LinkedHashMap<>();
        final Set<String> limits = new LinkedHashSet<>();
        final Map<MethodResult,Boolean> safeStatements = new LinkedHashMap<>();
        int nodes, steps, entrypoints;
        long deadline = System.nanoTime() + 5_000_000_000L;
        Engine(List<Source> sources) { this.sources = sources; }
        void tick() { if (++steps > 30000 || System.nanoTime() > deadline) throw new Budget(); }
        Result run() {
            var compiler = ToolProvider.getSystemJavaCompiler();
            if (compiler == null) return new Result(VERSION,"UNAVAILABLE",List.of(),List.of(),List.of(),List.of("JDK_PARSER_UNAVAILABLE"));
            parse(compiler);
            for (var m : methods) if (isEntry(m)) {
                entrypoints++;
                var env = new Env();
                m.fields().forEach((name,type)->{env.types.put(name,type);env.values.put(name,typed(m,type,Val.unknownValue()));});
                for (var p : m.tree().getParameters()) {
                    String type = resolve(m.unit(),p.getType().toString());
                    Val v = typed(m,type,Val.unknownValue());
                    if (requestType(type)) v=Val.object("REQUEST");
                    else if (springSource(m,p)) {
                        boolean scalar=Set.of("String","java.lang.String").contains(type);
                        boolean dto=annotation(m,p,"RequestBody")&&!scalar;
                        v=new Val(dto?"DTO":"VALUE",null,true,!scalar,List.of(loc(m,p,"REQUEST_INPUT")),null);
                        if(Set.of("int","long","short","byte","double","float","boolean").contains(type))v=new Val("VALUE",null,false,false,List.of(),null);
                    }
                    env.values.put(p.getName().toString(),v);env.types.put(p.getName().toString(),type);
                }
                try { call(m,env,0); }
                catch (Budget exhausted) { limits.add("FLOW_STEP_OR_TIME_LIMIT"); complete.put(m,false); break; }
            }
            var summaries = new ArrayList<MethodResult>();
            for (var m : executions.keySet()) {
                var observed=executions.get(m);
                boolean safe=!observed.isEmpty() && Boolean.TRUE.equals(complete.get(m))
                        && observed.stream().allMatch(u -> List.of("STATIC_QUERY","PARAMETERIZED_QUERY").contains(u.kind()))
                        && limits.isEmpty();
                summaries.add(new MethodResult(m.unit().source().path(),line(m,m.tree()),endLine(m),safe));
            }
            if(limits.isEmpty())for(var proof:safeStatements.entrySet())if(proof.getValue()&&summaries.size()<1000) {
                var p=proof.getKey();summaries.add(new MethodResult(p.filePath(),p.startLine(),p.endLine(),true));
            }
            var coverage = new ArrayList<FileResult>();
            for (var f : files) {
                var fm=methods.stream().filter(m->m.unit().source().path().equals(f.filePath())).toList();
                int syntax=fm.stream().mapToInt(this::sqlCalls).sum();
                int traced=(int)uses.values().stream().filter(u->u.location().filePath().equals(f.filePath())).count();
                var reasons=new LinkedHashSet<>(f.limitations());
                if (syntax>traced) reasons.add("SQL_CALLS_OUTSIDE_TRACED_FLOW");
                if (fm.stream().noneMatch(this::isEntry)) reasons.add("NO_VERIFIED_REQUEST_ENTRY");
                if (fm.stream().anyMatch(m->Boolean.FALSE.equals(complete.get(m)))) reasons.add("UNSUPPORTED_FLOW_OR_UNKNOWN_CALL");
                coverage.add(new FileResult(f.filePath(),f.parseStatus(),(int)fm.stream().filter(this::isEntry).count(),
                        (int)fm.stream().filter(executions::containsKey).count(),syntax,traced,List.copyOf(reasons)));
            }
            var notes=new ArrayList<>(limits);
            notes.add("BOUNDED_SPRING_AND_SERVLET_ONLY");notes.add("API_SHAPES_NO_TYPE_ATTRIBUTION_OR_RUNTIME_PROOF");
            notes.add("NO_TARGET_EXECUTION_OR_ANNOTATION_PROCESSING");
            return new Result(VERSION, sources.isEmpty()?"NOT_APPLICABLE":"PARTIAL",coverage,summaries,List.copyOf(uses.values()),notes);
        }
        void parse(JavaCompiler compiler) {
            var diagnostics=new DiagnosticCollector<JavaFileObject>();
            var inputs=new ArrayList<JavaFileObject>();
            var originals=new LinkedHashMap<URI,Source>();
            for(var source:sources) {
                URI uri=URI.create("string:///Input"+inputs.size()+".java");
                inputs.add(new SimpleJavaFileObject(uri,JavaFileObject.Kind.SOURCE) {
                    @Override public CharSequence getCharContent(boolean ignored){return source.content();}
                });
                originals.put(uri,source);
            }
            // SourcePositions retains JavacTrees and its compiler context. One task
            // per file kept a whole context per indexed method's Unit alive.
            // A single bounded parse-only task preserves cross-file ASTs without
            // attribution, compilation, source lookup or annotation processing.
            try(var manager=compiler.getStandardFileManager(diagnostics,Locale.ROOT,StandardCharsets.UTF_8)) {
                var task=(JavacTask)compiler.getTask(new StringWriter(),manager,diagnostics,
                        List.of("-proc:none","--release","17","-classpath","","-sourcepath",""),null,inputs);
                var parsed=task.parse();
                var positions=Trees.instance(task).getSourcePositions();
                var failed=new HashSet<URI>();boolean globalError=false;
                for(var diagnostic:diagnostics.getDiagnostics())if(diagnostic.getKind()==Diagnostic.Kind.ERROR) {
                    if(diagnostic.getSource()==null)globalError=true;
                    else failed.add(diagnostic.getSource().toUri());
                }
                for(var tree:parsed) {
                    var source=originals.get(tree.getSourceFile().toUri());
                    if(source==null)throw new IOException("SOURCE_IDENTITY");
                    if(globalError||failed.contains(tree.getSourceFile().toUri())) {
                        files.add(new FileResult(source.path(),"PARSE_FAILED",0,0,0,0,List.of("JAVA_SYNTAX_NOT_PARSED")));continue;
                    }
                    try {
                        tick();
                        new TreeScanner<Void,Integer>() {
                            @Override public Void scan(Tree node,Integer depth) {
                                if(node==null)return null;
                                if(++nodes>60000||depth>128||System.nanoTime()>deadline)throw new Budget();
                                return super.scan(node,depth+1);
                            }
                        }.scan(tree,0);
                        var imports=new HashMap<String,String>();
                        tree.getImports().stream().filter(i->!i.isStatic()).forEach(i->{
                            String name=i.getQualifiedIdentifier().toString();imports.put(name.endsWith(".*")?name:name.substring(name.lastIndexOf('.')+1),name);
                        });
                        var localTypes=new HashSet<String>();
                        new TreeScanner<Void,Void>() {
                            @Override public Void visitClass(ClassTree c,Void ignored){localTypes.add(c.getSimpleName().toString());return super.visitClass(c,ignored);}
                        }.scan(tree,null);
                        var unit=new Unit(source,tree,positions,imports,localTypes);
                        for(var t:tree.getTypeDecls())if(t instanceof ClassTree c)index(unit,c);
                        files.add(new FileResult(source.path(),"PARSED",0,0,0,0,List.of()));
                    }catch(Budget|StackOverflowError exhausted) {
                        files.add(new FileResult(source.path(),"LIMIT_EXCEEDED",0,0,0,0,List.of("AST_OR_TIME_LIMIT")));limits.add("AST_OR_TIME_LIMIT");
                    }
                }
                var seen=new HashSet<String>();files.forEach(f->seen.add(f.filePath()));
                for(var source:sources)if(!seen.contains(source.path()))
                    files.add(new FileResult(source.path(),"PARSE_FAILED",0,0,0,0,List.of("JAVA_UNIT_NOT_RETURNED")));
            }catch(IOException|RuntimeException|StackOverflowError failure) {
                methods.clear();files.clear();limits.add("JAVA_PARSER_BATCH_FAILED");
                for(var source:sources)files.add(new FileResult(source.path(),failure instanceof StackOverflowError?"LIMIT_EXCEEDED":"PARSE_FAILED",0,0,0,0,List.of("JAVA_PARSER_BATCH_FAILED")));
            }
        }
        void index(Unit unit, ClassTree owner) {
            var fields=new HashMap<String,String>();
            for (var member : owner.getMembers()) if (member instanceof VariableTree v) fields.put(v.getName().toString(),resolve(unit,v.getType().toString()));
            for (var member : owner.getMembers()) if (member instanceof MethodTree method && method.getBody()!=null) {
                if (methods.size()>=1000) { limits.add("METHOD_INDEX_LIMIT"); return; }
                methods.add(new Method(unit,owner,method,fields));
            }
        }
        String resolve(Unit u, String type) {
            String clean=type.replaceAll("<.*>","");
            if (clean.contains(".")) return clean;
            if (u.localTypes().contains(clean)) return "LOCAL:"+clean;
            if(u.imports().containsKey(clean))return u.imports().get(clean);
            var known=Set.of("Connection","Statement","PreparedStatement","CallableStatement","HttpServlet","HttpServletRequest","Cookie",
                    "RestController","RequestMapping","GetMapping","PostMapping","PutMapping","DeleteMapping","PatchMapping","RequestParam","RequestBody","PathVariable");
            if(known.contains(clean)) {
                var choices=u.imports().values().stream().filter(v->v.endsWith(".*")).map(v->v.substring(0,v.length()-1)+clean)
                        .filter(v->v.startsWith("org.springframework.web.bind.annotation.")&&clean.matches("RestController|.*Mapping|RequestParam|RequestBody|PathVariable")
                                ||v.startsWith("java.sql.")&&clean.matches("Connection|Statement|PreparedStatement|CallableStatement")
                                ||v.matches("(?:javax|jakarta)\\.servlet\\.http\\.(HttpServlet|HttpServletRequest|Cookie)")).toList();
                if(choices.size()==1)return choices.get(0);
            }
            return clean;
        }
        boolean annotation(Method m, VariableTree p, String name) {
            return p.getModifiers().getAnnotations().stream().anyMatch(a->resolve(m.unit(),a.getAnnotationType().toString()).equals("org.springframework.web.bind.annotation."+name));
        }
        boolean springSource(Method m, VariableTree p) { return annotation(m,p,"RequestParam")||annotation(m,p,"PathVariable")||annotation(m,p,"RequestBody"); }
        boolean isEntry(Method m) {
            boolean mapping=m.tree().getModifiers().getAnnotations().stream().anyMatch(a->Set.of("RequestMapping","GetMapping","PostMapping","PutMapping","DeleteMapping","PatchMapping").stream()
                    .anyMatch(n->resolve(m.unit(),a.getAnnotationType().toString()).equals("org.springframework.web.bind.annotation."+n)));
            boolean controller=m.owner().getModifiers().getAnnotations().stream().anyMatch(a->Set.of("org.springframework.web.bind.annotation.RestController","org.springframework.stereotype.Controller").contains(resolve(m.unit(),a.getAnnotationType().toString())));
            if (mapping && controller) return true;
            String parent=m.owner().getExtendsClause()==null?"":resolve(m.unit(),m.owner().getExtendsClause().toString());
            return Set.of("javax.servlet.http.HttpServlet","jakarta.servlet.http.HttpServlet").contains(parent)
                    && Set.of("doGet","doPost","service","doPut","doDelete").contains(m.tree().getName().toString())
                    && m.tree().getParameters().stream().anyMatch(p->requestType(resolve(m.unit(),p.getType().toString())));
        }
        boolean requestType(String type) { return Set.of("javax.servlet.http.HttpServletRequest","jakarta.servlet.http.HttpServletRequest").contains(type); }
        Val typed(Method m,String type,Val value) {
            String kind=switch(type) {
                case "java.sql.Connection" -> "CONNECTION";
                case "java.sql.Statement" -> "STATEMENT";
                case "org.springframework.jdbc.core.JdbcTemplate","org.springframework.jdbc.core.JdbcOperations" -> "JDBC";
                case "javax.servlet.http.Cookie","jakarta.servlet.http.Cookie" -> "COOKIE";
                case "javax.sql.DataSource" -> "DATASOURCE";
                default -> null;
            };
            return kind==null ? value : new Val(kind,value.constant(),value.input(),value.unknown()&&!value.type().equals("VALUE"),value.trace(),value.sql());
        }
        int line(Method m,Tree n) { long p=m.unit().positions().getStartPosition(m.unit().tree(),n);return p<0?1:(int)m.unit().tree().getLineMap().getLineNumber(p); }
        int endLine(Method m) { long p=m.unit().positions().getEndPosition(m.unit().tree(),m.tree());return p<0?line(m,m.tree()):(int)m.unit().tree().getLineMap().getLineNumber(Math.max(0,p-1)); }
        Location loc(Method m,Tree n,String kind) { String name=m.tree().getName().toString();long p=m.unit().positions().getStartPosition(m.unit().tree(),n);return new Location(m.unit().source().path(),line(m,n),p<0?1:(int)m.unit().tree().getLineMap().getColumnNumber(p),name.length()>100?"method":name,kind); }
        int sqlCalls(Method m) {
            int[] count={0};
            new TreeScanner<Void,Void>() {
                @Override public Void visitMethodInvocation(MethodInvocationTree n,Void x) { if (Set.of("execute","executeQuery","executeUpdate","executeLargeUpdate","executeBatch","query","queryForObject","queryForList","update","batchUpdate").contains(name(n)))count[0]++;return super.visitMethodInvocation(n,x); }
            }.scan(m.tree().getBody(),null);return count[0];
        }
        String name(MethodInvocationTree call) { return call.getMethodSelect() instanceof MemberSelectTree s?s.getIdentifier().toString():call.getMethodSelect().toString(); }
        Flow call(Method m,Env env,int depth) {
            if (depth>3) { env.partial=true;return new Flow(false,Val.unknownValue()); }
            executions.computeIfAbsent(m,k->new ArrayList<>());
            Flow flow=stmt(m,m.tree().getBody(),env,depth);
            boolean all=executions.get(m).size()>=sqlCalls(m) && !env.partial;
            complete.merge(m,all,(a,b)->a&&b);
            return flow;
        }
        Flow stmt(Method m,StatementTree node,Env env,int depth) {
            tick();
            if (node instanceof BlockTree block) {
                var before=new HashSet<>(env.values.keySet());
                var shadow=new HashMap<String,Val>();
                for (var s:block.getStatements()) {
                    if(s instanceof VariableTree v && before.contains(v.getName().toString()))shadow.put(v.getName().toString(),env.values.get(v.getName().toString()));
                    Flow f=stmt(m,s,env,depth);
                    if(f.stopped()) { restoreScope(env,before,shadow);return f; }
                }
                restoreScope(env,before,shadow);return Flow.next();
            }
            if (node instanceof VariableTree v) {
                Val value=v.getInitializer()==null?Val.unknownValue():eval(m,v.getInitializer(),env,depth);
                String type=v.getType()==null?"<inferred>":resolve(m.unit(),v.getType().toString());env.types.put(v.getName().toString(),type);
                proof(m,v,!value.input()&&!value.unknown()&&value.type().equals("VALUE")
                        &&(value.constant() instanceof String||Set.of("String","java.lang.String").contains(type)));
                value=typed(m,type,value);
                if(value.type().equals("STATEMENT")&&value.constant()==null)value=new Val("STATEMENT",m.unit().source().path()+":"+m.unit().positions().getStartPosition(m.unit().tree(),v),false,false,value.trace(),null);
                env.values.put(v.getName().toString(),value.step(loc(m,v,"VARIABLE")));return Flow.next();
            }
            if (node instanceof ExpressionStatementTree e) { eval(m,e.getExpression(),env,depth);return Flow.next(); }
            if (node instanceof ReturnTree r) return new Flow(true,r.getExpression()==null?Val.literal(null):eval(m,r.getExpression(),env,depth));
            if (node instanceof ThrowTree) return new Flow(true,Val.unknownValue());
            if (node instanceof IfTree branch) {
                Val condition=eval(m,branch.getCondition(),env,depth);
                if (condition.constant() instanceof Boolean b) return b?stmt(m,branch.getThenStatement(),env,depth):branch.getElseStatement()==null?Flow.next():stmt(m,branch.getElseStatement(),env,depth);
                var yes=env.copy();var no=env.copy();
                narrow(m,branch.getCondition(),yes,true);narrow(m,branch.getCondition(),no,false);
                Flow a=stmt(m,branch.getThenStatement(),yes,depth);
                Flow b=branch.getElseStatement()==null?Flow.next():stmt(m,branch.getElseStatement(),no,depth);
                if(a.stopped()&&!b.stopped())env.take(no);else if(b.stopped()&&!a.stopped())env.take(yes);else merge(env,yes,no);
                return new Flow(a.stopped()&&b.stopped(),join(a.value(),b.value()));
            }
            if (node instanceof TryTree attempt) {
                for(var r:attempt.getResources())if(r instanceof VariableTree v)stmt(m,v,env,depth);else if(r instanceof ExpressionTree e)eval(m,e,env,depth);
                var before=env.copy();var success=env.copy();Flow flow=stmt(m,attempt.getBlock(),success,depth);
                for(var catcher:attempt.getCatches()) {
                    var failed=before.copy();failed.values.put(catcher.getParameter().getName().toString(),Val.unknownValue());
                    Flow other=stmt(m,catcher.getBlock(),failed,depth);
                    if(!other.stopped())merge(success,success.copy(),failed);
                    flow=new Flow(flow.stopped()&&other.stopped(),join(flow.value(),other.value()));
                }
                env.take(success);if(attempt.getFinallyBlock()!=null)stmt(m,attempt.getFinallyBlock(),env,depth);return flow;
            }
            if (node instanceof EnhancedForLoopTree loop) {
                Val iterable=eval(m,loop.getExpression(),env,depth);var iteration=env.copy();
                iteration.values.put(loop.getVariable().getName().toString(),iterable.type().equals("COOKIE_ARRAY")?new Val("COOKIE",null,false,false,iterable.trace(),null):Val.unknownValue());
                stmt(m,loop.getStatement(),iteration,depth);merge(env,env.copy(),iteration);
                if(!iterable.type().equals("COOKIE_ARRAY"))env.partial=true;return Flow.next();
            }
            if (node instanceof EmptyStatementTree || node instanceof BreakTree) return Flow.next();
            env.partial=true;
            // Unsupported control flow cannot leave existing locals trusted afterwards.
            env.values.replaceAll((k,v)->v.uncertain());return Flow.next();
        }
        void restoreScope(Env env,Set<String> before,Map<String,Val> shadow) { env.values.keySet().removeIf(k->!before.contains(k));env.values.putAll(shadow); }
        void merge(Env target,Env a,Env b) {
            target.values.clear();var keys=new HashSet<>(a.values.keySet());keys.addAll(b.values.keySet());
            for(String key:keys)target.values.put(key,join(a.values.getOrDefault(key,Val.unknownValue()),b.values.getOrDefault(key,Val.unknownValue())));
            target.guardUnknown=a.guardUnknown||b.guardUnknown;target.partial=a.partial||b.partial;
            target.bindings.clear();a.bindings.forEach((k,v)->target.bindings.put(k,Math.min(v,b.bindings.getOrDefault(k,0))));
            target.batches.clear();var batchKeys=new HashSet<>(a.batches.keySet());batchKeys.addAll(b.batches.keySet());
            for(String key:batchKeys)target.batches.put(key,join(a.batches.getOrDefault(key,Val.unknownValue()),b.batches.getOrDefault(key,Val.unknownValue())));
        }
        void proof(Method m,Tree node,boolean safe) {
            String text=m.unit().source().content();long begin=m.unit().positions().getStartPosition(m.unit().tree(),node),end=m.unit().positions().getEndPosition(m.unit().tree(),node);
            if(begin<0||end<=begin||end>text.length()||safeStatements.size()>=500)return;
            int start=(int)begin,finish=(int)end;
            int first=text.lastIndexOf('\n',Math.max(0,start-1))+1,last=text.indexOf('\n',finish);
            if(last<0)last=text.length();
            if(!text.substring(first,start).isBlank()||!text.substring(finish,last).isBlank())return;
            safeStatements.merge(new MethodResult(m.unit().source().path(),line(m,node),(int)m.unit().tree().getLineMap().getLineNumber(Math.max(start,finish-1)),false),safe,(a,b)->a&&b);
        }
        Val join(Val a,Val b) {
            var trace=new ArrayList<Location>(a.trace());for(var l:b.trace())if(!trace.contains(l)&&trace.size()<20)trace.add(l);
            boolean sameType=a.type().equals(b.type());
            return new Val(sameType?a.type():"VALUE",Objects.equals(a.constant(),b.constant())?a.constant():null,
                    a.input()||b.input(),a.unknown()||b.unknown()||!sameType,List.copyOf(trace),
                    a.sql()!=null&&b.sql()!=null?join(a.sql(),b.sql()):null);
        }
        void narrow(Method m,ExpressionTree tree,Env env,boolean truth) {
            if(tree instanceof ParenthesizedTree p){narrow(m,p.getExpression(),env,truth);return;}
            if(tree instanceof UnaryTree u && u.getKind()==Tree.Kind.LOGICAL_COMPLEMENT){narrow(m,u.getExpression(),env,!truth);return;}
            if(tree instanceof BinaryTree b && Set.of(Tree.Kind.EQUAL_TO,Tree.Kind.NOT_EQUAL_TO).contains(b.getKind())) {
                boolean equals=truth==(b.getKind()==Tree.Kind.EQUAL_TO);
                if(equals && b.getLeftOperand() instanceof IdentifierTree id && b.getRightOperand() instanceof LiteralTree literal)env.values.put(id.getName().toString(),Val.literal(literal.getValue()));
                return;
            }
            if(tree instanceof MethodInvocationTree c && name(c).equals("equals") && c.getMethodSelect() instanceof MemberSelectTree s && c.getArguments().size()==1
                    && s.getExpression() instanceof IdentifierTree variable && Set.of("String","java.lang.String").contains(env.types.getOrDefault(variable.getName().toString(),""))) {
                if(truth && s.getExpression() instanceof IdentifierTree id && c.getArguments().get(0) instanceof LiteralTree literal)env.values.put(id.getName().toString(),Val.literal(literal.getValue()));
                return;
            }
            if(tree instanceof MethodInvocationTree c && c.getArguments().stream().anyMatch(a->a instanceof IdentifierTree id&&env.values.getOrDefault(id.getName().toString(),Val.unknownValue()).input()))env.guardUnknown=true;
        }
        Val eval(Method m,ExpressionTree expression,Env env,int depth) {
            tick();if(expression==null)return Val.unknownValue();
            if(expression instanceof LiteralTree literal)return Val.literal(literal.getValue());
            if(expression instanceof IdentifierTree id)return env.values.getOrDefault(id.getName().toString(),Val.unknownValue());
            if(expression instanceof ParenthesizedTree p)return eval(m,p.getExpression(),env,depth);
            if(expression instanceof TypeCastTree cast) {
                Val value=eval(m,cast.getExpression(),env,depth);
                env.partial=true;return value.uncertain();
            }
            if(expression instanceof AssignmentTree assignment) {
                if(!(assignment.getVariable() instanceof IdentifierTree id)){env.partial=true;return eval(m,assignment.getExpression(),env,depth).uncertain();}
                Val value=eval(m,assignment.getExpression(),env,depth).step(loc(m,assignment,"ASSIGNMENT"));env.values.put(id.getName().toString(),value);return value;
            }
            if(expression instanceof CompoundAssignmentTree assignment && assignment.getVariable() instanceof IdentifierTree id) {
                Val left=env.values.getOrDefault(id.getName().toString(),Val.unknownValue());
                Val right=eval(m,assignment.getExpression(),env,depth);
                Val result=assignment.getKind()==Tree.Kind.PLUS_ASSIGNMENT?plus(left,right):join(left,right).uncertain();
                env.values.put(id.getName().toString(),result.step(loc(m,assignment,"SQL_CONSTRUCTION")));return result;
            }
            if(expression instanceof BinaryTree binary) {
                Val left=eval(m,binary.getLeftOperand(),env,depth);
                if(binary.getKind()==Tree.Kind.CONDITIONAL_AND && Boolean.FALSE.equals(left.constant()))return Val.literal(false);
                if(binary.getKind()==Tree.Kind.CONDITIONAL_OR && Boolean.TRUE.equals(left.constant()))return Val.literal(true);
                if(Set.of(Tree.Kind.CONDITIONAL_AND,Tree.Kind.CONDITIONAL_OR).contains(binary.getKind())&&!(left.constant() instanceof Boolean)) {
                    var skipped=env.copy();var evaluated=env.copy();
                    Val right=eval(m,binary.getRightOperand(),evaluated,depth);merge(env,skipped,evaluated);
                    return calculate(binary.getKind(),left,right);
                }
                Val right=eval(m,binary.getRightOperand(),env,depth);
                return binary.getKind()==Tree.Kind.PLUS?plus(left,right).step(loc(m,binary,"SQL_CONSTRUCTION")):calculate(binary.getKind(),left,right);
            }
            if(expression instanceof ConditionalExpressionTree ternary) {
                Val condition=eval(m,ternary.getCondition(),env,depth);
                if(condition.constant() instanceof Boolean b)return eval(m,b?ternary.getTrueExpression():ternary.getFalseExpression(),env,depth);
                var a=env.copy();var b=env.copy();Val yes=eval(m,ternary.getTrueExpression(),a,depth),no=eval(m,ternary.getFalseExpression(),b,depth);merge(env,a,b);return join(yes,no);
            }
            if(expression instanceof UnaryTree unary) {
                Val v=eval(m,unary.getExpression(),env,depth);
                if(unary.getKind()==Tree.Kind.LOGICAL_COMPLEMENT && v.constant() instanceof Boolean b)return Val.literal(!b);
                if(unary.getKind()==Tree.Kind.UNARY_MINUS && v.constant() instanceof Number n)return Val.literal(n instanceof Long?-n.longValue():(int)-n.intValue());
                if(unary.getExpression() instanceof IdentifierTree id)env.values.put(id.getName().toString(),v.uncertain());
                env.partial=true;return v.uncertain();
            }
            if(expression instanceof MemberSelectTree member) {
                if(member.getExpression().toString().equals("this"))return env.values.getOrDefault(member.getIdentifier().toString(),Val.unknownValue());
                Val base=eval(m,member.getExpression(),env,depth);
                if(base.type().equals("DTO"))return base.step(loc(m,member,"REQUEST_BODY_FIELD"));
                return Val.unknownValue();
            }
            if(expression instanceof MethodInvocationTree invocation)return invoke(m,invocation,env,depth);
            if(expression instanceof NewArrayTree array) {
                Val result=Val.literal(null);if(array.getInitializers()!=null)for(var e:array.getInitializers())result=join(result,eval(m,e,env,depth));return result;
            }
            if(expression instanceof NewClassTree object) { for(var a:object.getArguments())eval(m,a,env,depth);env.partial=true;return Val.unknownValue(); }
            env.partial=true;return Val.unknownValue();
        }
        Val plus(Val a,Val b) {
            if(!a.input()&&!b.input()&&!a.unknown()&&!b.unknown()&&a.constant()!=null&&b.constant()!=null) {
                if(a.constant() instanceof Number x && b.constant() instanceof Number y)return Val.literal(number(x,y,x.longValue()+y.longValue()));
                String text=String.valueOf(a.constant())+b.constant();return text.length()>100_000?Val.unknownValue():Val.literal(text);
            }
            Val result=join(a,b);return new Val("VALUE",null,result.input(),result.unknown(),result.trace(),null);
        }
        Val calculate(Tree.Kind op,Val a,Val b) {
            Object x=a.constant(),y=b.constant();
            if(x instanceof Number n && y instanceof Number p) {
                if(n instanceof Float||n instanceof Double||p instanceof Float||p instanceof Double)return Val.unknownValue();
                long l=n.longValue(),r=p.longValue();
                return switch(op) {
                    case MINUS -> Val.literal(number(n,p,l-r));case MULTIPLY -> Val.literal(number(n,p,l*r));
                    case DIVIDE -> r==0?Val.unknownValue():Val.literal(number(n,p,l/r));case REMAINDER -> r==0?Val.unknownValue():Val.literal(number(n,p,l%r));
                    case GREATER_THAN -> Val.literal(l>r);case LESS_THAN -> Val.literal(l<r);
                    case GREATER_THAN_EQUAL -> Val.literal(l>=r);case LESS_THAN_EQUAL -> Val.literal(l<=r);
                    case EQUAL_TO -> Val.literal(l==r);case NOT_EQUAL_TO -> Val.literal(l!=r);default -> Val.unknownValue();
                };
            }
            if(x!=null&&y!=null&&Set.of(Tree.Kind.EQUAL_TO,Tree.Kind.NOT_EQUAL_TO).contains(op))return Val.literal(Objects.equals(x,y)==(op==Tree.Kind.EQUAL_TO));
            if(x instanceof Boolean l && y instanceof Boolean r) {
                if(op==Tree.Kind.CONDITIONAL_AND)return Val.literal(l&&r);if(op==Tree.Kind.CONDITIONAL_OR)return Val.literal(l||r);
            }
            return Val.unknownValue();
        }
        Object number(Number a,Number b,long value) {
            if(a instanceof Float||a instanceof Double||b instanceof Float||b instanceof Double)return null;
            if(a instanceof Long||b instanceof Long)return Long.valueOf(value);
            return Integer.valueOf((int)value);
        }
        Val invoke(Method m,MethodInvocationTree node,Env env,int depth) {
            String method=name(node),receiverText="";
            Val receiver=Val.unknownValue();
            if(node.getMethodSelect() instanceof MemberSelectTree s) { receiverText=s.getExpression().toString();receiver=eval(m,s.getExpression(),env,depth); }
            var args=new ArrayList<Val>();for(var a:node.getArguments())args.add(eval(m,a,env,depth));
            if(receiver.type().equals("REQUEST")) {
                if(Set.of("getParameter","getHeader","getQueryString","getPathInfo").contains(method))return new Val("VALUE",null,true,false,List.of(loc(m,node,"REQUEST_INPUT")),null);
                if(method.equals("getCookies"))return new Val("COOKIE_ARRAY",null,false,false,List.of(loc(m,node,"REQUEST_COOKIE")),null);
            }
            if(receiver.type().equals("COOKIE")&&method.equals("getValue"))return new Val("VALUE",null,true,false,receiver.trace(),null).step(loc(m,node,"COOKIE_VALUE"));
            if(receiver.type().equals("DTO")&&args.isEmpty()&&method.startsWith("get"))return receiver.step(loc(m,node,"REQUEST_BODY_FIELD"));
            if(receiver.type().equals("DATASOURCE")&&method.equals("getConnection"))return Val.object("CONNECTION");
            if(receiver.type().equals("CONNECTION")) {
                if(method.equals("createStatement"))return Val.object("STATEMENT").step(loc(m,node,"STATEMENT_CREATION"));
                if(Set.of("prepareStatement","prepareCall").contains(method)&&!args.isEmpty()) {
                    // Construction is not execution, but an unexecuted dynamic query is not a safe-method proof.
                    if(args.get(0).input()||args.get(0).unknown())env.partial=true;
                    String ref=m.unit().source().path()+":"+line(m,node)+":"+m.unit().positions().getStartPosition(m.unit().tree(),node);
                    env.bindings.put(ref,0);
                    return new Val("PREPARED",ref,false,false,List.of(),args.get(0).step(loc(m,node,"SQL_PREPARATION")));
                }
            }
            if(Set.of("STATEMENT","PREPARED").contains(receiver.type())&&method.equals("addBatch")&&receiver.constant() instanceof String ref) {
                Val sql=args.isEmpty()?receiver.sql():args.get(0);
                if(sql!=null)env.batches.merge(ref,sql,this::join);return Val.literal(null);
            }
            if(Set.of("STATEMENT","PREPARED").contains(receiver.type())&&Set.of("execute","executeQuery","executeUpdate","executeLargeUpdate","executeBatch").contains(method)) {
                Val sql=method.equals("executeBatch")&&receiver.constant() instanceof String ref?env.batches.get(ref):args.isEmpty()?receiver.sql():args.get(0);
                sql=sql==null?Val.unknownValue():sql;
                var trace=new ArrayList<>(sql.trace());for(var l:receiver.trace())if(!trace.contains(l)&&trace.size()<20)trace.add(l);
                record(m,node,new Val("VALUE",sql.constant(),sql.input(),sql.unknown(),trace,null),method,env,
                        args.isEmpty()&&receiver.constant() instanceof String ref?env.bindings.getOrDefault(ref,0):0);return Val.unknownValue();
            }
            if(receiver.type().equals("JDBC")&&Set.of("query","queryForObject","queryForList","update","batchUpdate","execute").contains(method)&&!args.isEmpty()) {
                record(m,node,args.get(0),"JdbcTemplate."+method,env,args.size()>1?1:0);return Val.unknownValue();
            }
            if(Set.of("setString","setInt","setLong","setObject","setBoolean","setNull","setDouble","setBigDecimal","setBytes").contains(method)
                    &&receiver.type().equals("PREPARED")&&args.size()>=2&&receiver.constant() instanceof String ref) {
                env.bindings.merge(ref,1,Integer::sum);return Val.literal(null);
            }
            if(method.equals("concat")&&args.size()==1 && receiver.type().equals("VALUE"))return plus(receiver,args.get(0));
            if(method.equals("toString")&&args.isEmpty()&&!receiver.unknown())return receiver;
            String owner=resolve(m.unit(),receiverText);
            if(owner.equals("java.net.URLDecoder")&&method.equals("decode")&&!args.isEmpty())return args.get(0).step(loc(m,node,"URL_DECODE"));
            if(Set.of("Integer","Long","java.lang.Integer","java.lang.Long").contains(owner)&&Set.of("parseInt","parseLong").contains(method)
                    &&!m.unit().localTypes().contains(owner)&&!env.values.containsKey(receiverText))return new Val("VALUE",null,false,false,List.of(),null);
            if(method.equals("equals")&&args.size()==1 && receiver.constant()!=null&&args.get(0).constant()!=null)return Val.literal(Objects.equals(receiver.constant(),args.get(0).constant()));
            boolean localReceiver=receiverText.isEmpty()||receiverText.equals("this");
            List<Method> targets=methods.stream().filter(t->t.tree().getName().contentEquals(method)&&t.tree().getParameters().size()==args.size()
                    && (localReceiver&&t.owner()==m.owner()
                    || t.tree().getModifiers().getFlags().contains(javax.lang.model.element.Modifier.STATIC)
                       && (qualified(t).equals(owner)||qualified(t).equals((m.unit().tree().getPackageName()==null?"":m.unit().tree().getPackageName()+".")+owner)))).toList();
            if(targets.size()==1&&depth<3) {
                Method target=targets.get(0);var child=new Env();
                target.fields().forEach((k,t)->{child.types.put(k,t);child.values.put(k,typed(target,t,Val.unknownValue()));});
                for(int i=0;i<args.size();i++) {
                    var parameter=target.tree().getParameters().get(i);String parameterName=parameter.getName().toString();
                    child.types.put(parameterName,resolve(target.unit(),parameter.getType().toString()));
                    child.values.put(parameterName,args.get(i).step(loc(m,node,"FUNCTION_ARGUMENT")));
                }
                Flow result=call(target,child,depth+1);env.partial|=child.partial;return result.stopped()?result.value():Val.unknownValue();
            }
            if(args.stream().anyMatch(v->v.input()||Set.of("PREPARED","STATEMENT","CONNECTION").contains(v.type()))
                    &&!receiverText.equals("System.out")&&!receiverText.equals("System.err"))env.partial=true;
            Val unknown=receiver;for(var a:args)unknown=join(unknown,a);
            return unknown.uncertain();
        }
        String qualified(Method m) { return (m.unit().tree().getPackageName()==null?"":m.unit().tree().getPackageName()+".")+m.owner().getSimpleName(); }
        void record(Method m,MethodInvocationTree node,Val sql,String api,Env env,int binding) {
            if(uses.size()>=200){limits.add("RESULT_LIMIT");env.partial=true;return;}
            String kind=sql.unknown()||env.guardUnknown?"UNRESOLVED_QUERY":sql.input()?"INPUT_IN_QUERY":binding>0?"PARAMETERIZED_QUERY":"STATIC_QUERY";
            var reasons=kind.equals("UNRESOLVED_QUERY")?List.of("SQL_VALUE_OR_GUARD_UNRESOLVED"):List.<String>of();
            var use=new Use(kind,api,loc(m,node,"SQL_EXECUTION"),sql.trace(),binding,reasons);
            String key=use.location().filePath()+":"+use.location().line()+":"+use.location().column()+":"+api;
            var prior=uses.get(key);
            if(prior!=null&&!prior.equals(use)) {
                String combined=prior.kind().equals("UNRESOLVED_QUERY")||kind.equals("UNRESOLVED_QUERY")?"UNRESOLVED_QUERY"
                        :prior.kind().equals("INPUT_IN_QUERY")||kind.equals("INPUT_IN_QUERY")?"INPUT_IN_QUERY":kind;
                var trace=new ArrayList<>(prior.trace());for(var l:use.trace())if(!trace.contains(l)&&trace.size()<20)trace.add(l);
                use=new Use(combined,api,use.location(),trace,binding,combined.equals("UNRESOLVED_QUERY")?List.of("MULTIPLE_CALL_CONTEXTS_UNRESOLVED"):List.of());
            }
            uses.put(key,use);executions.computeIfAbsent(m,k->new ArrayList<>()).add(use);
        }
    }
}
