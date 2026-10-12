package com.securedeploy.ai.semantic;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.project.model.ProjectFileType;
import com.securedeploy.project.model.ProjectStructure;
import com.sun.source.tree.*;
import com.sun.source.util.JavacTask;
import com.sun.source.util.TreeScanner;
import com.sun.source.util.Trees;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;
import javax.tools.*;
import org.springframework.stereotype.Component;

@Component
public class SecuritySliceCollector {
    private final SemanticProperties limits;
    private final SemanticSanitizer sanitizer;
    public SecuritySliceCollector(SemanticProperties limits, SemanticSanitizer sanitizer) {
        this.limits = limits; this.sanitizer = sanitizer;
    }
    public record Collection(List<SecuritySlice> slices, int omittedSlices, List<String> limitations, boolean available) {
        public static Collection empty() { return new Collection(List.of(), 0, List.of(), true); }
    }
    private record Call(String type, String method, int arity) { }
    private record Method(String type, String name, int arity, String signature, String file, int start, int end,
                          String content, String endpoint, String verb, boolean authorization, boolean security,
                          List<String> parameters, List<Call> calls, int priority, boolean truncated) { }

    public Collection collect(ProjectStructure project) {
        var compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) return new Collection(List.of(), 0, List.of("JDK parser unavailable"), false);
        List<Method> methods = new ArrayList<>();
        List<String> notes = new ArrayList<>();
        int files = 0, chars = 0, skipped = 0;
        long deadline = System.nanoTime() + 8_000_000_000L;
        var javaFiles = project.analysisFiles().stream().filter(f -> f.type() == ProjectFileType.JAVA)
                .sorted(Comparator.comparingInt((ProjectFile f) -> filePriority(f.relativePath())).thenComparing(ProjectFile::relativePath)).toList();
        for (var file : javaFiles) {
            int size = file.lines().stream().mapToInt(s -> s.length() + 1).sum();
            if (files >= limits.getMaxIndexedFiles() || chars + size > limits.getMaxIndexedChars()
                    || size > 100000 || System.nanoTime() > deadline || methods.size() >= 3000
                    || !safePath(file.relativePath())) { skipped++; continue; }
            files++; chars += size;
            try { parse(compiler, file, methods); }
            catch (RuntimeException | java.io.IOException failure) { skipped++; }
        }
        if (skipped > 0) notes.add("Skipped/unparsed Java files: " + skipped);
        notes.add("Direct syntactic calls only; no type resolution, full call graph, taint or reachability proof.");
        var entries = methods.stream().filter(m -> m.endpoint() != null)
                .sorted(Comparator.comparingInt(Method::priority).thenComparing(Method::file).thenComparingInt(Method::start)).toList();
        List<SecuritySlice> slices = new ArrayList<>();
        for (var entry : entries.stream().limit(limits.getMaxSlices()).toList()) {
            LinkedHashSet<Method> selected = new LinkedHashSet<>();
            selected.add(entry);
            List<Method> frontier = List.of(entry);
            for (int depth = 0; depth < 2 && selected.size() < 4; depth++) {
                List<Method> next = new ArrayList<>();
                for (var source : frontier) for (var call : source.calls()) {
                    var targets = methods.stream().filter(m -> m.type().equals(call.type()) && m.name().equals(call.method()) && m.arity() == call.arity()).toList();
                    if (targets.size() == 1 && selected.size() < 4 && selected.add(targets.get(0))) next.add(targets.get(0));
                }
                frontier = next;
            }
            methods.stream().filter(Method::security).sorted(Comparator.comparing(Method::file).thenComparingInt(Method::start))
                    .limit(2).forEach(selected::add);
            List<SecuritySlice.CodeContext> contexts = selected.stream().filter(m -> !m.content().isBlank()).map(m ->
                    new SecuritySlice.CodeContext(id(m.file()+":"+m.signature()+":"+m.start()), m.file(), m.start(), m.end(),
                            m.signature(), m.authorization(), m.content())).toList();
            if (contexts.isEmpty() || !contexts.get(0).functionName().equals(entry.signature())) continue;
            List<String> limitations = new ArrayList<>(notes);
            limitations.add("Global filters/interceptors, dynamic dispatch and ownership checks may exist outside this slice.");
            if (selected.stream().anyMatch(Method::truncated)) limitations.add("One or more method excerpts were truncated at a complete line.");
            slices.add(new SecuritySlice(id(entry.file()+":"+entry.signature()+":"+entry.endpoint()), entry.signature(), entry.endpoint(),
                    entry.verb(), selected.stream().anyMatch(Method::authorization) ? "AUTHORIZATION_DECLARATION_PRESENT_NOT_VERIFIED" : "UNKNOWN_NOT_PROOF_OF_ABSENCE",
                    entry.parameters(), contexts, List.of(), List.copyOf(limitations)));
        }
        return new Collection(List.copyOf(slices), Math.max(0, entries.size()-slices.size()), List.copyOf(notes), true);
    }

    private void parse(JavaCompiler compiler, ProjectFile file, List<Method> methods) throws java.io.IOException {
        String source = String.join("\n", file.lines());
        var diagnostics = new DiagnosticCollector<JavaFileObject>();
        var input = new SimpleJavaFileObject(URI.create("string:///Slice.java"), JavaFileObject.Kind.SOURCE) {
            @Override public CharSequence getCharContent(boolean ignored) { return source; }
        };
        try (var manager = compiler.getStandardFileManager(diagnostics, Locale.ROOT, StandardCharsets.UTF_8)) {
            // parse() only: never analyze(), generate(), load classes or run annotation processors.
            var task = (JavacTask) compiler.getTask(new java.io.StringWriter(), manager, diagnostics,
                    List.of("-proc:none", "--release", "17"), null, List.of(input));
            var units = task.parse();
            var positions = Trees.instance(task).getSourcePositions();
            for (var unit : units) {
                if (diagnostics.getDiagnostics().stream().anyMatch(d -> d.getKind() == Diagnostic.Kind.ERROR)) throw new IllegalArgumentException("Unparsed source");
                List<int[]> literalRanges = new ArrayList<>();
                new TreeScanner<Void,Void>() {
                    @Override public Void visitLiteral(LiteralTree literal, Void ignored) {
                        if (literal.getValue() instanceof String || literal.getValue() instanceof Character) {
                            long start = positions.getStartPosition(unit,literal), end = positions.getEndPosition(unit,literal);
                            if (start>=0 && end>start && end<=source.length()) literalRanges.add(new int[]{(int)start,(int)end});
                        }
                        return null;
                    }
                }.scan(unit,null);
                StringBuilder masked = new StringBuilder(source);
                literalRanges.sort(Comparator.comparingInt((int[] range) -> range[0]).reversed());
                for (var range : literalRanges) {
                    long newlines = source.substring(range[0],range[1]).chars().filter(c -> c=='\n').count();
                    masked.replace(range[0],range[1],"[REDACTED_SECRET]"+"\n".repeat((int)newlines));
                }
                List<String> safeLines = Arrays.asList(sanitizer.source(masked.toString()).split("\n",-1));
                String packageName = unit.getPackageName()==null ? "" : unit.getPackageName().toString();
                Map<String,String> imports = new HashMap<>();
                unit.getImports().stream().filter(i -> !i.isStatic() && !i.getQualifiedIdentifier().toString().endsWith(".*"))
                        .forEach(i -> imports.put(simpleType(i.getQualifiedIdentifier().toString()),i.getQualifiedIdentifier().toString()));
                for (var tree : unit.getTypeDecls()) if (tree instanceof ClassTree type) {
                    String typeName = type.getSimpleName().toString();
                    String typeId = packageName.isEmpty() ? typeName : packageName+"."+typeName;
                    Map<String, String> fields = new HashMap<>();
                    for (var member : type.getMembers()) if (member instanceof VariableTree field)
                        fields.put(field.getName().toString(), qualifiedType(field.getType().toString(),packageName,imports));
                    String prefix = mapping(type.getModifiers().getAnnotations()).path;
                    boolean classAuthorization = authorization(type.getModifiers().getAnnotations());
                    boolean security = typeName.matches(".*(SecurityConfig|Filter|Interceptor|AuthenticationProvider).*?");
                    for (var member : type.getMembers()) if (member instanceof MethodTree method && method.getReturnType() != null) {
                        long a = positions.getStartPosition(unit, method), b = positions.getEndPosition(unit, method);
                        if (a < 0 || b <= a) continue;
                        int start = (int) unit.getLineMap().getLineNumber(a), end = (int) unit.getLineMap().getLineNumber(b-1);
                        String signature = typeName + "." + method.getName() + "(" + method.getParameters().stream()
                                .map(v -> v.getType().toString()).collect(java.util.stream.Collectors.joining(",")) + ")";
                        if (!signature.equals(sanitizer.text(signature, 300))) continue;
                        StringBuilder excerpt = new StringBuilder();
                        int last = start - 1;
                        for (int line = start; line <= end && line <= safeLines.size(); line++) {
                            String value = safeLines.get(line-1);
                            if (excerpt.length()+value.length()+1 > limits.getMaxSnippetChars()) break;
                            excerpt.append(value).append('\n'); last = line;
                        }
                        var mapping = mapping(method.getModifiers().getAnnotations());
                        String endpoint = mapping.present && prefix != null && mapping.path != null ? cleanPath(prefix+"/"+mapping.path) : null;
                        Map<String, String> variables = new HashMap<>(fields);
                        method.getParameters().forEach(v -> variables.put(v.getName().toString(), qualifiedType(v.getType().toString(),packageName,imports)));
                        List<Call> calls = new ArrayList<>();
                        if (method.getBody() != null) new TreeScanner<Void, Void>() {
                            @Override public Void visitClass(ClassTree node, Void unused) { return null; }
                            @Override public Void visitMethodInvocation(MethodInvocationTree node, Void unused) {
                                String target = null, name = null;
                                if (node.getMethodSelect() instanceof MemberSelectTree s) {
                                    String receiver = s.getExpression().toString().replaceFirst("^this\\.", "");
                                    target = receiver.equals("this") ? typeId : variables.get(receiver);
                                    name = s.getIdentifier().toString();
                                } else if (node.getMethodSelect() instanceof IdentifierTree s) { target = typeId; name = s.getName().toString(); }
                                if (target != null) calls.add(new Call(target, name, node.getArguments().size()));
                                return super.visitMethodInvocation(node, unused);
                            }
                        }.scan(method.getBody(), null);
                        boolean auth = classAuthorization || authorization(method.getModifiers().getAnnotations());
                        String signal = (typeName+" "+method.getName()+" "+Objects.toString(endpoint, "")+" "+calls).toLowerCase(Locale.ROOT);
                        int priority = signal.matches(".*(auth|login|session|jwt|security).*?") ? 0
                                : signal.contains("admin") ? 1 : signal.matches(".*(upload|file|path|process|exec|http|url|serializ).*?") ? 2
                                : signal.matches(".*(user|account|payment|transfer|profile).*?") ? 3 : 4;
                        methods.add(new Method(typeId, method.getName().toString(), method.getParameters().size(), signature,
                                file.relativePath(), start, last, excerpt.toString(), endpoint, mapping.verb, auth, security,
                                method.getParameters().stream().map(v -> sanitizer.text(v.getName().toString(),120)).toList(), calls, priority, last < end));
                    }
                }
            }
        }
    }
    private record Mapping(boolean present, String path, String verb) { }
    private Mapping mapping(List<? extends AnnotationTree> annotations) {
        for (var annotation : annotations) {
            String name = simpleType(annotation.getAnnotationType().toString());
            if (!Set.of("RequestMapping", "GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping").contains(name)) continue;
            String path = "", verb = name.equals("RequestMapping") ? "ANY" : name.replace("Mapping", "").toUpperCase(Locale.ROOT);
            for (var arg : annotation.getArguments()) {
                String key = arg instanceof AssignmentTree a ? a.getVariable().toString() : "value";
                ExpressionTree value = arg instanceof AssignmentTree a ? a.getExpression() : arg;
                if (key.equals("value") || key.equals("path")) {
                    if (value instanceof LiteralTree literal && literal.getValue() instanceof String s) path = s;
                    else path = null;
                }
                if (key.equals("method")) {
                    var v = value instanceof NewArrayTree array && array.getInitializers() != null && array.getInitializers().size()==1 ? array.getInitializers().get(0) : value;
                    if (v instanceof MemberSelectTree select && Set.of("GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS").contains(select.getIdentifier().toString())) verb = select.getIdentifier().toString();
                }
            }
            return new Mapping(true, path, verb);
        }
        return new Mapping(false, "", "ANY");
    }
    private String cleanPath(String path) {
        String normalized = path.replaceAll("/+", "/");
        return normalized.length() <= 200 && normalized.matches("[/A-Za-z0-9_{}.*:-]+") && safePath(normalized) ? normalized : null;
    }
    private boolean safePath(String path) {
        // A normal multi-segment path is not an opaque base64 credential. Check segments separately.
        return path.length()<=500 && Arrays.stream(path.split("/",-1)).allMatch(part -> part.equals(sanitizer.text(part,200)));
    }
    private static boolean authorization(List<? extends AnnotationTree> annotations) {
        return annotations.stream().anyMatch(a -> Set.of("PreAuthorize","PostAuthorize","Secured","RolesAllowed").contains(simpleType(a.getAnnotationType().toString())));
    }
    private static int filePriority(String path) { return path.contains("Controller") ? 0 : path.contains("Security") ? 1 : path.contains("Service") ? 2 : 3; }
    private static String simpleType(String value) { String raw = value.replaceAll("<.*>", ""); return raw.substring(raw.lastIndexOf('.')+1); }
    private static String qualifiedType(String value, String packageName, Map<String,String> imports) {
        String raw = value.replaceAll("<.*>", "");
        if (raw.contains(".")) return raw;
        return imports.getOrDefault(raw,packageName.isEmpty() ? raw : packageName+"."+raw);
    }
    static String id(String value) { return UUID.nameUUIDFromBytes(value.getBytes(StandardCharsets.UTF_8)).toString(); }
}
