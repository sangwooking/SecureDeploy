package com.securedeploy.analysis.javaflow;

import com.sun.source.tree.*;
import com.sun.source.util.*;
import javax.tools.*;
import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;
import javax.xml.stream.*;

/** Trusted JDK-only worker. Target text is parsed, never attributed, compiled or loaded. */
public final class JavaSqlWorker {
    public static final String VERSION = "java-sql-v3";
    public record Source(String path, String content) { }
    public record Location(String filePath, int line, int column, String functionName, String kind) { }
    public record FileResult(String filePath, String parseStatus, int entrypoints, int functions,
                             int sqlCallSites, int tracedCallSites, List<String> limitations) { }
    public record MethodResult(String filePath, int startLine, int endLine, boolean safeForLegacy) { }
    public record Use(String kind, String api, Location location, List<Location> trace,
                      int bindingCalls, List<String> limitations) { }
    public record DataAccess(String framework, String status, String operation, Location location,
                             Location declaration, List<Location> trace, List<String> limitations) { }
    public record Result(String version, String status, List<FileResult> files, List<MethodResult> methods,
                         List<Use> uses, List<String> limitations, List<DataAccess> dataAccess) {
        public Result { dataAccess=dataAccess==null?List.of():List.copyOf(dataAccess); }
        public Result(String version,String status,List<FileResult> files,List<MethodResult> methods,List<Use> uses,List<String> limitations) {
            this(version,status,files,methods,uses,limitations,List.of());
        }
    }

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
            var xml=new ArrayList<Source>();
            int first=input.read();
            int xmlCount=first<0?0:bounded((first<<24)|(input.readUnsignedByte()<<16)|(input.readUnsignedByte()<<8)|input.readUnsignedByte(),100-count);
            for(int i=0;i<xmlCount;i++) {
                String path=input.readUTF();int size=bounded(input.readInt(),400_000);byte[] bytes=input.readNBytes(size);
                if(bytes.length!=size||path.length()>1024)throw new IOException("INVALID_INPUT");
                String content=new String(bytes,StandardCharsets.UTF_8);chars+=content.length();
                if(content.length()>100_000||chars>1_000_000)throw new IOException("INPUT_LIMIT");
                xml.add(new Source(path,content));
            }
            write(output, new Engine(sources,xml).run());
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
        out.writeInt(r.dataAccess().size());
        for(var a:r.dataAccess()) {
            out.writeUTF(a.framework());out.writeUTF(a.status());out.writeUTF(a.operation());location(out,a.location());
            out.writeBoolean(a.declaration()!=null);if(a.declaration()!=null)location(out,a.declaration());
            out.writeInt(a.trace().size());for(var l:a.trace())location(out,l);strings(out,a.limitations());
        }
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
        var notes=strings(in);var accesses=new ArrayList<DataAccess>();
        for(int i=0,n=bounded(in.readInt(),200);i<n;i++) {
            String framework=in.readUTF(),state=in.readUTF(),operation=in.readUTF();Location call=location(in),decl=in.readBoolean()?location(in):null;
            var trace=new ArrayList<Location>();for(int j=0,k=bounded(in.readInt(),20);j<k;j++)trace.add(location(in));
            accesses.add(new DataAccess(framework,state,operation,call,decl,List.copyOf(trace),strings(in)));
        }
        return new Result(version, status, files, methods, uses, notes,List.copyOf(accesses));
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
    private record TypeInfo(Unit unit,ClassTree tree,Map<String,String> fields) { }
    private record Declaration(TypeInfo owner,MethodTree tree) { }
    private record MapperSql(String namespace,String id,String sql,boolean dynamic,Location location) { }
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
        final List<Source> xmlSources;
        final Map<String,TypeInfo> types=new LinkedHashMap<>();
        final Set<String> ambiguousTypes=new HashSet<>();
        final List<Declaration> declarations=new ArrayList<>();
        final Map<String,List<MapperSql>> mapperSql=new HashMap<>();
        final LinkedHashMap<String,DataAccess> dataAccess=new LinkedHashMap<>();
        final Map<TypeInfo,Map<String,Boolean>> injectionCache=new HashMap<>();
        final List<FileResult> files = new ArrayList<>();
        final List<Method> methods = new ArrayList<>();
        final Map<Method, List<Use>> executions = new LinkedHashMap<>();
        final Map<Method, Boolean> complete = new HashMap<>();
        final LinkedHashMap<String,Use> uses = new LinkedHashMap<>();
        final Set<String> limits = new LinkedHashSet<>();
        final Map<MethodResult,Boolean> safeStatements = new LinkedHashMap<>();
        int nodes, steps, entrypoints;
        long deadline = System.nanoTime() + 5_000_000_000L;
        Engine(List<Source> sources,List<Source> xmlSources) { this.sources = sources;this.xmlSources=xmlSources; }
        void tick() { if (++steps > 30000 || System.nanoTime() > deadline) throw new Budget(); }
        Result run() {
            var compiler = ToolProvider.getSystemJavaCompiler();
            if (compiler == null) return new Result(VERSION,"UNAVAILABLE",List.of(),List.of(),List.of(),List.of("JDK_PARSER_UNAVAILABLE"));
            parse(compiler);
            parseMappers();
            for (var m : methods) if (isEntry(m)) {
                entrypoints++;
                var env = new Env();
                try {
                initialize(m,env);
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
                call(m,env,0); }
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
            return new Result(VERSION, sources.isEmpty()?"NOT_APPLICABLE":"PARTIAL",coverage,summaries,List.copyOf(uses.values()),notes,List.copyOf(dataAccess.values()));
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
                methods.clear();types.clear();declarations.clear();files.clear();limits.add("JAVA_PARSER_BATCH_FAILED");
                for(var source:sources)files.add(new FileResult(source.path(),failure instanceof StackOverflowError?"LIMIT_EXCEEDED":"PARSE_FAILED",0,0,0,0,List.of("JAVA_PARSER_BATCH_FAILED")));
            }
        }
        void index(Unit unit, ClassTree owner) {
            var fields=new HashMap<String,String>();
            for (var member : owner.getMembers()) if (member instanceof VariableTree v) fields.put(v.getName().toString(),resolve(unit,v.getType().toString()));
            var info=new TypeInfo(unit,owner,fields);String fqn=typeName(info);
            if(types.putIfAbsent(fqn,info)!=null){limits.add("AMBIGUOUS_TYPE_IDENTITY");ambiguousTypes.add(fqn);}
            for(var member:owner.getMembers())if(member instanceof MethodTree method) {
                if(declarations.size()>=1000){limits.add("METHOD_INDEX_LIMIT");break;}
                declarations.add(new Declaration(info,method));
            }
            for (var member : owner.getMembers()) if (member instanceof MethodTree method && method.getBody()!=null) {
                if(declarations.stream().noneMatch(d->d.owner()==info&&d.tree()==method))continue;
                if (methods.size()>=1000) { limits.add("METHOD_INDEX_LIMIT"); return; }
                methods.add(new Method(unit,owner,method,fields));
            }
        }
        String typeName(TypeInfo info) {
            return (info.unit().tree().getPackageName()==null?"":info.unit().tree().getPackageName()+".")+info.tree().getSimpleName();
        }
        TypeInfo type(Unit unit,String name) {
            String resolved=resolve(unit,name);
            String local=(unit.tree().getPackageName()==null?"":unit.tree().getPackageName()+".")+resolved;
            String key=types.containsKey(resolved)?resolved:local;
            return ambiguousTypes.contains(key)?null:types.get(key);
        }
        boolean ann(Unit unit,AnnotationTree annotation,String fqn) {
            String name=resolve(unit,annotation.getAnnotationType().toString());
            if(name.equals(fqn))return true;
            return !name.contains(".")&&name.equals(fqn.substring(fqn.lastIndexOf('.')+1))
                    &&unit.imports().values().stream().filter(v->v.endsWith(".*")).count()==1
                    &&unit.imports().containsKey(fqn.substring(0,fqn.lastIndexOf('.')+1)+"*");
        }
        boolean component(TypeInfo info) {
            return info.tree().getModifiers().getAnnotations().stream().anyMatch(a->Set.of("Service","Repository","Component","Controller").stream()
                    .anyMatch(n->ann(info.unit(),a,"org.springframework.stereotype."+n)));
        }
        boolean conditional(TypeInfo info) {
            return info.tree().getModifiers().getAnnotations().stream().anyMatch(a->{String n=a.getAnnotationType().toString();return n.endsWith("Profile")||n.contains("Conditional")||n.endsWith("Qualifier");});
        }
        boolean base(TypeInfo info,Set<String> wanted,Set<String> seen,int depth) {
            if(info==null||depth>3||!seen.add(typeName(info)))return false;
            var parents=new ArrayList<Tree>(info.tree().getImplementsClause());
            if(info.tree().getExtendsClause()!=null)parents.add(info.tree().getExtendsClause());
            for(var parent:parents) {
                String name=resolve(info.unit(),parent.toString());if(wanted.contains(name))return true;
                TypeInfo resolved=type(info.unit(),name);
                if(resolved!=null&&wanted.contains(typeName(resolved)))return true;
                if(base(resolved,wanted,seen,depth+1))return true;
            }
            return false;
        }
        String framework(TypeInfo info) {
            if(info==null)return "UNKNOWN";
            if(base(info,Set.of("org.springframework.data.jpa.repository.JpaRepository","org.springframework.data.repository.Repository","org.springframework.data.repository.CrudRepository","org.springframework.data.repository.ListCrudRepository","org.springframework.data.repository.PagingAndSortingRepository"),new HashSet<>(),0))return "SPRING_DATA_JPA";
            if(base(info,Set.of("com.baomidou.mybatisplus.extension.service.impl.ServiceImpl","com.baomidou.mybatisplus.extension.service.IService","com.baomidou.mybatisplus.core.mapper.BaseMapper"),new HashSet<>(),0))return "MYBATIS_PLUS";
            if(mapperSql.containsKey(typeName(info))||info.tree().getModifiers().getAnnotations().stream().anyMatch(a->ann(info.unit(),a,"org.apache.ibatis.annotations.Mapper")))return "MYBATIS";
            return "APPLICATION";
        }
        TypeInfo implementation(TypeInfo declared) {
            if(declared==null||conditional(declared))return null;
            if(declared.tree().getKind()!=Tree.Kind.INTERFACE&&!declared.tree().getModifiers().getFlags().contains(javax.lang.model.element.Modifier.ABSTRACT))return declared;
            var candidates=types.values().stream().filter(t->!ambiguousTypes.contains(typeName(t))&&component(t)
                    &&t.tree().getKind()!=Tree.Kind.INTERFACE&&!t.tree().getModifiers().getFlags().contains(javax.lang.model.element.Modifier.ABSTRACT)
                    &&base(t,Set.of(typeName(declared)),new HashSet<>(),0)).toList();
            if(candidates.size()==1&&!conditional(candidates.get(0)))return candidates.get(0);
            if(candidates.isEmpty()&&!framework(declared).equals("APPLICATION"))return declared;
            return null;
        }
        boolean injected(TypeInfo info,String field) {
            var cache=injectionCache.computeIfAbsent(info,k->new HashMap<>());
            if(cache.containsKey(field))return cache.get(field);
            boolean result=computeInjected(info,field);cache.put(field,result);return result;
        }
        boolean computeInjected(TypeInfo info,String field) {
            var variable=info.tree().getMembers().stream().filter(t->t instanceof VariableTree v&&v.getName().contentEquals(field)).map(t->(VariableTree)t).findFirst();
            if(variable.isEmpty())return false;
            var annotations=variable.get().getModifiers().getAnnotations();
            if(annotations.stream().anyMatch(a->a.getAnnotationType().toString().endsWith("Qualifier")))return false;
            boolean[] mutated={false};
            for(var member:info.tree().getMembers())if(member instanceof MethodTree method&&method.getReturnType()!=null) {
                new TreeScanner<Void,Void>() {
                    @Override public Void scan(Tree tree,Void unused){if(tree!=null)tick();return super.scan(tree,unused);}
                    boolean target(Tree tree){return tree.toString().equals(field)||tree.toString().equals("this."+field);}
                    @Override public Void visitAssignment(AssignmentTree tree,Void unused){if(target(tree.getVariable()))mutated[0]=true;return super.visitAssignment(tree,unused);}
                    @Override public Void visitCompoundAssignment(CompoundAssignmentTree tree,Void unused){if(target(tree.getVariable()))mutated[0]=true;return super.visitCompoundAssignment(tree,unused);}
                }.scan(method.getBody(),null);
            }
            if(mutated[0])return false;
            if(annotations.stream().anyMatch(a->a.getArguments().isEmpty()&&(ann(info.unit(),a,"org.springframework.beans.factory.annotation.Autowired")||ann(info.unit(),a,"jakarta.inject.Inject")||ann(info.unit(),a,"javax.inject.Inject"))))return true;
            var constructors=declarations.stream().filter(d->d.owner()==info&&d.tree().getReturnType()==null).toList();
            if(constructors.size()!=1||constructors.get(0).tree().getBody()==null)return false;
            var constructor=constructors.get(0).tree();
            if(constructor.getModifiers().getAnnotations().stream().anyMatch(a->a.getAnnotationType().toString().endsWith("Qualifier")))return false;
            if(constructor.getBody().getStatements().stream().anyMatch(s->!(s instanceof ExpressionStatementTree e
                    &&e.getExpression() instanceof AssignmentTree a&&a.getVariable() instanceof MemberSelectTree member
                    &&member.getExpression().toString().equals("this")&&a.getExpression() instanceof IdentifierTree)))return false;
            if(constructor.getBody().getStatements().stream().filter(s->s instanceof ExpressionStatementTree e
                    &&e.getExpression() instanceof AssignmentTree a&&a.getVariable().toString().equals("this."+field)).count()!=1)return false;
            return constructor.getBody().getStatements().stream().anyMatch(s->s instanceof ExpressionStatementTree e&&e.getExpression() instanceof AssignmentTree a
                    &&a.getVariable() instanceof MemberSelectTree member&&member.getExpression().toString().equals("this")&&member.getIdentifier().contentEquals(field)
                    &&a.getExpression() instanceof IdentifierTree parameter&&constructor.getParameters().stream().anyMatch(p->p.getName().contentEquals(parameter.getName())
                    &&p.getModifiers().getAnnotations().stream().noneMatch(annotation->annotation.getAnnotationType().toString().endsWith("Qualifier"))
                    &&resolve(info.unit(),p.getType().toString()).equals(info.fields().get(field))));
        }
        void initialize(Method method,Env env) {
            TypeInfo info=types.get(qualified(method));
            method.fields().forEach((name,t)->{
                env.types.put(name,t);Val value=typed(method,t,Val.unknownValue());
                if(info!=null&&injected(info,name)) {
                    TypeInfo target=implementation(type(info.unit(),t));
                    if(target!=null)value=new Val("BEAN:"+typeName(target),null,false,false,List.of(),null);
                }
                env.values.put(name,value);
            });
            if(info!=null&&info.tree().getExtendsClause() instanceof ParameterizedTypeTree parent
                    &&resolve(info.unit(),parent.getType().toString()).equals("com.baomidou.mybatisplus.extension.service.impl.ServiceImpl")
                    &&!parent.getTypeArguments().isEmpty()&&!info.fields().containsKey("baseMapper")) {
                TypeInfo mapper=type(info.unit(),parent.getTypeArguments().get(0).toString());
                if(mapper!=null){env.values.put("baseMapper",new Val("BEAN:"+typeName(mapper),null,false,false,List.of(),null));env.types.put("baseMapper",typeName(mapper));}
            }
        }
        String annotationSql(Declaration declaration,String fqn) {
            for(var annotation:declaration.tree().getModifiers().getAnnotations())if(ann(declaration.owner().unit(),annotation,fqn)) {
                for(var argument:annotation.getArguments()) {
                    Tree value=argument instanceof AssignmentTree assignment&&assignment.getVariable().toString().equals("value")?assignment.getExpression():argument;
                    if(value instanceof LiteralTree literal&&literal.getValue() instanceof String sql)return sql;
                }
                return null;
            }
            return null;
        }
        boolean declaredAccess(Method method,MethodInvocationTree node,TypeInfo receiver,List<Val> args,Env env) {
            String operation=name(node),family=framework(receiver);
            var candidates=declarations.stream().filter(d->d.owner()==receiver&&d.tree().getName().contentEquals(operation)&&d.tree().getParameters().size()==args.size()).toList();
            var trace=new ArrayList<Location>();for(var value:args)for(var loc:value.trace())if(!trace.contains(loc)&&trace.size()<20)trace.add(loc);
            Location call=loc(method,node,"DATA_ACCESS_CALL");
            if(family.equals("SPRING_DATA_JPA")) {
                if(candidates.size()>1){access(family,"UNKNOWN",operation,call,null,trace,List.of("AMBIGUOUS_METHOD_DECLARATION"));return true;}
                String sql=candidates.isEmpty()?null:annotationSql(candidates.get(0),"org.springframework.data.jpa.repository.Query");
                String status=sql==null?"DERIVED_OPERATION_CONTRACT":sql.contains("#{")||sql.contains("${")?"UNKNOWN":"DECLARED_QUERY_CONTRACT";
                boolean namedQuery=candidates.stream().anyMatch(d->d.tree().getModifiers().getAnnotations().stream().anyMatch(a->ann(receiver.unit(),a,"org.springframework.data.jpa.repository.Query")));
                if(sql==null&&namedQuery)status="UNKNOWN";
                if(!namedQuery&&!operation.matches("(?:find|read|get|query|search|stream|count|exists|delete|remove|save|flush).*"))status="UNKNOWN";
                access(family,status,operation,call,null,trace,List.of("ORM_SQL_AND_PROXY_RUNTIME_NOT_VERIFIED","CUSTOM_REPOSITORY_IMPLEMENTATION_NOT_VERIFIED"));return true;
            }
            var statements=mapperSql.getOrDefault(typeName(receiver),List.of()).stream().filter(s->s.id().equals(operation)).toList();
            Declaration declaration=candidates.size()==1?candidates.get(0):null;
            String sql=null;Location source=null;boolean dynamic=false;
            if(statements.size()==1){var s=statements.get(0);sql=s.sql();source=s.location();dynamic=s.dynamic();}
            else if(statements.isEmpty()&&declaration!=null)for(String annotation:List.of("Select","Insert","Update","Delete")) {
                sql=annotationSql(declaration,"org.apache.ibatis.annotations."+annotation);
                if(sql!=null){source=new Location(receiver.unit().source().path(),(int)receiver.unit().tree().getLineMap().getLineNumber(receiver.unit().positions().getStartPosition(receiver.unit().tree(),declaration.tree())),1,operation,"SQL_DECLARATION");break;}
            }
            if(sql!=null||family.equals("MYBATIS")||family.equals("MYBATIS_PLUS")) {
                if(sql==null||dynamic||declaration==null||statements.size()>1||declaration.tree().getBody()!=null) {
                    access(family.equals("APPLICATION")?"MYBATIS":family,"UNKNOWN",operation,call,source,trace,List.of("DYNAMIC_INHERITED_OR_AMBIGUOUS_DATA_ACCESS_NOT_MODELED"));return true;
                }
                if(sql.isBlank()||sql.contains("<script")||sql.contains("#{#")||sql.contains("${@")) {
                    access("MYBATIS","UNKNOWN",operation,call,source,trace,List.of("DYNAMIC_SQL_DECLARATION_NOT_MODELED"));return true;
                }
                var parameters=new HashMap<String,Val>();
                for(int i=0;i<declaration.tree().getParameters().size();i++) {
                    var parameter=declaration.tree().getParameters().get(i);
                    for(var annotation:parameter.getModifiers().getAnnotations())if(ann(receiver.unit(),annotation,"org.apache.ibatis.annotations.Param"))
                        for(var argument:annotation.getArguments())if(argument instanceof LiteralTree literal&&literal.getValue() instanceof String key)parameters.merge(key,args.get(i),(first,second)->Val.unknownValue());
                }
                Val query=Val.literal(sql);int bindings=0;
                var matcher=java.util.regex.Pattern.compile("([#$])\\{([^}]{1,256})}").matcher(sql);
                while(matcher.find()) {
                    tick();String key=matcher.group(2).split(",",2)[0].strip();
                    if(matcher.group(1).equals("#")){bindings++;continue;}
                    Val value=parameters.getOrDefault(key,Val.unknownValue());
                    query=plus(query,value);
                }
                if(source!=null)query=query.step(source);
                access("MYBATIS",query.unknown()?"UNKNOWN":query.input()?"INPUT_SUBSTITUTION":"DECLARED_VALUE_BINDING",operation,call,source,trace,List.of("FRAMEWORK_PROXY_RUNTIME_NOT_VERIFIED"));
                record(method,node,query,"MyBatis."+operation,env,bindings);return true;
            }
            return false;
        }
        void access(String framework,String status,String operation,Location location,Location declaration,List<Location> trace,List<String> notes) {
            if(dataAccess.size()>=200){limits.add("DATA_ACCESS_RESULT_LIMIT");return;}
            String key=location.filePath()+":"+location.line()+":"+location.column()+":"+framework+":"+operation;
            var value=new DataAccess(framework,status,operation.length()>100?"operation":operation,location,declaration,trace.stream().distinct().limit(20).toList(),notes);
            var prior=dataAccess.get(key);
            if(prior!=null&&!prior.equals(value))value=new DataAccess(framework,"UNKNOWN",value.operation(),location,declaration,List.of(),List.of("MULTIPLE_CALL_CONTEXTS"));
            dataAccess.put(key,value);
        }
        void parseMappers() {
            for(var source:xmlSources) {
                var location=new Location(source.path(),1,1,"mapper","MAPPER_DOCUMENT");
                try {
                    tick();var factory=XMLInputFactory.newFactory();
                    factory.setProperty(XMLInputFactory.SUPPORT_DTD,false);factory.setProperty("javax.xml.stream.isSupportingExternalEntities",false);
                    factory.setXMLResolver((publicId,systemId,base,namespace)->{throw new XMLStreamException("EXTERNAL_LOADING_DISABLED");});
                    var reader=factory.createXMLStreamReader(new StringReader(source.content()));
                    String namespace=null,id=null;int depth=0,statementDepth=-1;boolean dynamic=false;
                    Location declaration=null;var sql=new StringBuilder();
                    try {
                        while(reader.hasNext()) {
                            tick();int event=reader.next();
                            if(event==XMLStreamConstants.DTD&&reader.getText().contains("["))throw new XMLStreamException("INTERNAL_DTD_DISABLED");
                            if(event==XMLStreamConstants.START_ELEMENT) {
                                depth++;
                                if(depth>128)throw new XMLStreamException("XML_DEPTH_LIMIT");
                                String tag=reader.getLocalName();
                                if(depth==1&&tag.equals("mapper")&&(reader.getNamespaceURI()==null||reader.getNamespaceURI().isEmpty())) {
                                    namespace=reader.getAttributeValue(null,"namespace");
                                    if(namespace==null||!namespace.matches("[A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*)+"))throw new XMLStreamException("MAPPER_IDENTITY");
                                } else if(namespace!=null&&depth==2&&Set.of("select","update","insert","delete").contains(tag)) {
                                    id=reader.getAttributeValue(null,"id");statementDepth=depth;dynamic=reader.getNamespaceURI()!=null&&!reader.getNamespaceURI().isEmpty();sql.setLength(0);
                                    declaration=new Location(source.path(),reader.getLocation().getLineNumber(),Math.max(1,reader.getLocation().getColumnNumber()),"mapper","SQL_DECLARATION");
                                } else if(statementDepth>0)dynamic=true;
                            }else if((event==XMLStreamConstants.CHARACTERS||event==XMLStreamConstants.CDATA)&&statementDepth>0)sql.append(reader.getText());
                            else if(event==XMLStreamConstants.END_ELEMENT) {
                                if(depth==statementDepth) {
                                    if(id==null||!id.matches("[A-Za-z_$][\\w$]*"))throw new XMLStreamException("STATEMENT_IDENTITY");
                                    var statement=new MapperSql(namespace,id,sql.toString(),dynamic,declaration);
                                    mapperSql.computeIfAbsent(namespace,k->new ArrayList<>()).add(statement);
                                    if(mapperSql.values().stream().mapToInt(List::size).sum()>1000)throw new Budget();
                                    statementDepth=-1;id=null;
                                }
                                depth--;
                            }
                        }
                    }finally{reader.close();}
                    access("MYBATIS",namespace==null?"NOT_APPLICABLE":"PARSED_DECLARATIONS","mapper",location,null,List.of(),List.of("NO_EXTERNAL_DTD_ENTITY_OR_XINCLUDE_LOADING"));
                }catch(Exception failure) {
                    if(failure instanceof Budget)limits.add("MAPPER_STEP_OR_TIME_LIMIT");
                    mapperSql.values().forEach(list->list.removeIf(s->s.location().filePath().equals(source.path())));
                    access("MYBATIS","NOT_INSPECTED","mapper",location,null,List.of(),List.of("XML_PARSE_OR_BUDGET_FAILURE"));
                }
            }
        }
        String resolve(Unit u, String type) {
            String clean=type.replaceAll("<.*>","");
            if (clean.contains(".")) return clean;
            if (u.localTypes().contains(clean)) return (u.tree().getPackageName()==null?"":u.tree().getPackageName()+".")+clean;
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
            TypeInfo bean=receiver.type().startsWith("BEAN:")?types.get(receiver.type().substring(5)):null;
            List<Method> targets=methods.stream().filter(t->!ambiguousTypes.contains(qualified(t))&&t.tree().getName().contentEquals(method)&&t.tree().getParameters().size()==args.size()
                    && (localReceiver&&t.owner()==m.owner()
                    || bean!=null&&t.owner()==bean.tree()&&!t.tree().getModifiers().getFlags().contains(javax.lang.model.element.Modifier.STATIC)
                    || t.tree().getModifiers().getFlags().contains(javax.lang.model.element.Modifier.STATIC)
                       && (qualified(t).equals(owner)||qualified(t).equals((m.unit().tree().getPackageName()==null?"":m.unit().tree().getPackageName()+".")+owner)))).toList();
            TypeInfo accessType=bean!=null?bean:localReceiver?types.get(qualified(m)):null;
            if(targets.isEmpty()&&accessType!=null&&declaredAccess(m,node,accessType,args,env)){env.partial=true;return Val.unknownValue();}
            if(targets.size()==1&&depth<3) {
                Method target=targets.get(0);var child=new Env();
                initialize(target,child);
                for(int i=0;i<args.size();i++) {
                    var parameter=target.tree().getParameters().get(i);String parameterName=parameter.getName().toString();
                    child.types.put(parameterName,resolve(target.unit(),parameter.getType().toString()));
                    child.values.put(parameterName,args.get(i).step(loc(m,node,"FUNCTION_ARGUMENT")));
                }
                if(target.owner()!=m.owner())access("APPLICATION","RESOLVED_CALL",method,loc(m,node,"APPLICATION_CALL"),loc(target,target.tree(),"METHOD_DECLARATION"),args.stream().flatMap(v->v.trace().stream()).distinct().limit(20).toList(),List.of("BOUNDED_SOURCE_TYPE_RESOLUTION"));
                Flow result=call(target,child,depth+1);env.partial|=child.partial;return result.stopped()?result.value().step(loc(m,node,"METHOD_RETURN")):Val.unknownValue();
            }
            if(args.stream().anyMatch(Val::input)&&!receiverText.equals("System.out")&&!receiverText.equals("System.err"))
                access("APPLICATION","UNKNOWN",method,loc(m,node,"APPLICATION_CALL"),null,args.stream().flatMap(v->v.trace().stream()).distinct().limit(20).toList(),List.of(targets.size()>1?"AMBIGUOUS_OVERLOAD_OR_TARGET":depth>=3?"CALL_DEPTH_LIMIT":"RECEIVER_OR_IMPLEMENTATION_NOT_VERIFIED"));
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
