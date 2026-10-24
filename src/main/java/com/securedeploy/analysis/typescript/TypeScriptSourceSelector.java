package com.securedeploy.analysis.typescript;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.project.model.ProjectFileType;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Pattern;
import com.securedeploy.project.coverage.CoverageRecorder;

/** Bounded scheduling hints, never entrypoint, authorization or vulnerability proof. */
final class TypeScriptSourceSelector {
    static final int MAX_FILES=100, MAX_FILE_CHARS=100_000, MAX_TOTAL_CHARS=1_000_000;
    private static final int HINT_FILES=1000, HINT_CHARS=1_000_000, PREFIX_CHARS=16_000;
    private static final Pattern IMPORT=Pattern.compile("(?:\\bfrom\\s*|\\bimport\\s*|\\brequire\\s*\\(\\s*)['\"](\\.[^'\"\\r\\n]{1,240})['\"]");
    private static final Pattern HTTP_EXPORT=Pattern.compile("\\bexport\\s+(?:async\\s+)?function\\s+(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\\b|\\bexport\\s+const\\s+(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\\b");
    private static final Pattern SERVER_USE=Pattern.compile("\\b(?:fetch|eval|exec|execSync)\\s*\\(|\\.\\s*(?:query|prepare)\\s*\\(|child_process|process\\.env|Deno\\.env");
    private static final Pattern EXPRESS_RUNTIME=Pattern.compile("\\brequire\\s*\\(\\s*['\"]express['\"]\\s*\\)|\\bimport\\s+(?:(?!type\\b)[A-Za-z_$][\\w$]*(?:\\s*,[^;\\r\\n]+)?|\\*\\s+as\\s+[A-Za-z_$][\\w$]*|\\{\\s*Router\\b[^}\\r\\n]*\\})\\s+from\\s*['\"]express['\"]");
    record Choice(ProjectFile file,String reason,int priority,int characters,boolean sql) { }
    record Plan(List<Choice> selected,List<Choice> omitted,Map<String,String> omissions,boolean hintsComplete) {
        ServerAnalysisSnapshot.SelectionCoverage coverage() {
            var counts=new TreeMap<String,Integer>();omissions.values().forEach(r->counts.merge(r,1,Integer::sum));
            long js=omitted.stream().filter(c->!c.sql()).count(),sql=omitted.stream().filter(Choice::sql).count();
            long selectedSql=selected.stream().filter(Choice::sql).count();
            return new ServerAnalysisSnapshot.SelectionCoverage(selected.size()+omitted.size(),selected.size(),omitted.size(),
                    (int)Math.max(0,js-100)+(int)Math.max(0,sql-(100-selectedSql)),selected.stream().mapToInt(Choice::characters).sum(),counts);
        }
    }

    static Plan select(List<ProjectFile> input) {
        var manifests=NodeManifestMetadata.read(input);
        var packages=new HashMap<String,Map<String,String>>();manifests.worker().forEach(m->packages.put(m.get("filePath"),m));
        var js=input.stream().filter(f->f.relativePath().matches(".*(?:\\.[jt]sx?|\\.[cm]js)$"))
                .sorted(Comparator.comparing(ProjectFile::relativePath)).toList();
        var sql=input.stream().filter(f->f.type()==ProjectFileType.SUPABASE_SQL)
                .sorted(Comparator.comparing(ProjectFile::relativePath)).toList();
        Map<String,Choice> choices=new TreeMap<>();Map<String,Set<String>> edges=new TreeMap<>();
        Map<String,String> specs=new HashMap<>();Set<String> ambiguous=new HashSet<>();
        for(var f:js) {
            String p=f.relativePath(),stem=p.replaceFirst("\\.(?:[jt]sx?|[cm]js)$","");
            for(String key:List.of(p,stem))if(specs.putIfAbsent(key,p)!=null)ambiguous.add(key);
        }
        ambiguous.forEach(specs::remove);
        int configCharacters=TypeScriptConfigMetadata.read(input).stream().mapToInt(c->c.getOrDefault("content","").length()).sum();
        int hints=0,characters=manifests.characters()+configCharacters;boolean complete=manifests.complete();
        var texts=new HashMap<String,String>();
        var hintOrder=js.stream().sorted(Comparator.comparingInt((ProjectFile f)->convention(f.relativePath()))
                .thenComparing(ProjectFile::relativePath)).toList();
        int probe=Math.min(1024,Math.max(1,HINT_CHARS/2/Math.max(1,Math.min(js.size(),HINT_FILES))));
        for(var f:hintOrder) {
            String p=f.relativePath();int size=length(f);String reason="TS_DETERMINISTIC_FALLBACK";int priority=90;
            var refs=new TreeSet<String>();edges.put(p,refs);
            if(size<=MAX_FILE_CHARS&&hints<HINT_FILES&&characters+Math.min(size,probe)<=HINT_CHARS) {
                String text=prefix(f,probe);hints++;characters+=text.length();texts.put(p,text);
                reason=hint(p,text);priority=priority(reason);
            } else if(size<=MAX_FILE_CHARS){complete=false;reason="TS_SELECTION_HINT_LIMIT";}
            choices.put(p,new Choice(f,reason,priority,size,false));
        }
        // Manifest paths are scheduling hints only; no exported initializer is invoked.
        for(String seed:manifests.seeds()) {
            String target=resolveHint(seed,specs,packages);
            if(target==null)continue;
            var old=choices.get(target);
            if(old.priority()>0)choices.put(target,new Choice(old.file(),"TS_NODE_MANIFEST_ENTRY_HINT",0,old.characters(),false));
        }
        // Probe broadly before expanding relevant modules. Reuse one global hint
        // budget; imports and sink-shaped uses remain scheduling hints, never proof.
        var queue=new PriorityQueue<Choice>(Comparator.comparingInt(Choice::priority).thenComparing(c->c.file().relativePath()));
        queue.addAll(choices.values());var expanded=new HashSet<String>();
        while(!queue.isEmpty()) {
            var queued=queue.remove();String p=queued.file().relativePath();var current=choices.get(p);
            if(!texts.containsKey(p)||!expanded.add(p))continue;
            String text=texts.get(p);int cap=current.priority()<90?MAX_FILE_CHARS:PREFIX_CHARS;
            int available=Math.min(cap,text.length()+HINT_CHARS-characters);
            if(available>text.length()) {
                String next=prefix(current.file(),available);characters+=next.length()-text.length();text=next;texts.put(p,text);
            }
            String own=hint(p,text);
            if(priority(own)<current.priority()) {
                current=new Choice(current.file(),own,priority(own),current.characters(),false);choices.put(p,current);
            }
            var refs=references(p,text,specs,packages);edges.put(p,refs);
            if(current.priority()<3)for(String target:refs) {
                var old=choices.get(target);int depth=current.priority()+1;
                if(old.priority()>depth) {
                    var related=new Choice(old.file(),"TS_RELATED_IMPORT_HINT",depth,old.characters(),false);
                    choices.put(target,related);queue.add(related);
                }
            }
            if(text.length()<current.characters())complete=false;
        }
        boolean express=choices.values().stream().anyMatch(c->c.reason().equals("TS_EXPRESS_MODULE_HINT"));
        if(express)for(var c:List.copyOf(choices.values()))if(c.reason().equals("TS_RELATED_IMPORT_HINT")
                &&SERVER_USE.matcher(texts.getOrDefault(c.file().relativePath(),"")).find())
            choices.put(c.file().relativePath(),new Choice(c.file(),"TS_SERVER_USE_IMPORT_HINT",c.priority(),c.characters(),false));
        var ordered=choices.values().stream().sorted(Comparator.comparingInt(Choice::priority)
                .thenComparingInt(c->c.reason().equals("TS_SERVER_USE_IMPORT_HINT")?0:1)
                .thenComparing(c->c.file().relativePath())).toList();
        var policies=sql.stream().map(f->new Choice(f,"TS_POLICY_SQL_INPUT",0,length(f),true)).toList();
        var selected=new LinkedHashMap<String,Choice>();
        // Soft reservations: 24 relevant + 8 general JS, and up to 68 SQL slots.
        // Every unused reservation is reclaimed without increasing the global caps.
        take(ordered.stream().filter(c->c.priority()<90).toList(),selected,24,250_000);
        take(ordered.stream().filter(c->c.priority()>=90).toList(),selected,selected.size()+8,350_000);
        take(ordered,selected,32,350_000);
        int jsCount=selected.size(),jsChars=selected.values().stream().mapToInt(Choice::characters).sum();
        take(policies,selected,jsCount+68,jsChars+650_000);
        take(ordered.stream().filter(c->c.priority()<90).toList(),selected,MAX_FILES,MAX_TOTAL_CHARS);
        take(policies,selected,MAX_FILES,MAX_TOTAL_CHARS);
        take(ordered,selected,MAX_FILES,MAX_TOTAL_CHARS);
        var omitted=new ArrayList<Choice>();var omissions=new TreeMap<String,String>();
        for(var c:concat(ordered,policies))if(!selected.containsKey(c.file().relativePath())) {
            omitted.add(c);String reason=CoverageRecorder.safePath(c.file().relativePath()).equals("[redacted-path]")?"SENSITIVE_PATH_OMITTED"
                    :c.characters()>MAX_FILE_CHARS?"SOURCE_FILE_SIZE_LIMIT":selected.size()>=MAX_FILES?"SOURCE_FILE_COUNT_LIMIT":"SOURCE_TOTAL_CHAR_LIMIT";
            omissions.put(c.file().relativePath(),reason);
        }
        return new Plan(List.copyOf(selected.values()),List.copyOf(omitted),Map.copyOf(omissions),complete);
    }
    private static void take(List<Choice> candidates,Map<String,Choice> selected,int count,int chars) {
        int total=selected.values().stream().mapToInt(Choice::characters).sum();
        for(var c:candidates) {
            if(selected.containsKey(c.file().relativePath()))continue;
            if(selected.size()>=Math.min(count,MAX_FILES))break;
            if(c.characters()>MAX_FILE_CHARS||total+c.characters()>Math.min(chars,MAX_TOTAL_CHARS)
                    ||CoverageRecorder.safePath(c.file().relativePath()).equals("[redacted-path]"))continue;
            selected.put(c.file().relativePath(),c);total+=c.characters();
        }
    }
    private static List<Choice> concat(List<Choice> a,List<Choice> b){var all=new ArrayList<>(a);all.addAll(b);return all;}
    private static int priority(String reason){return switch(reason){
        case "TS_DENO_REGISTRATION_HINT","TS_NEXT_ROUTE_EXPORT_HINT","TS_EXPRESS_MODULE_HINT" -> 0;
        case "TS_SUPABASE_CLIENT_MODULE_HINT","TS_EDGE_FUNCTION_CONVENTION_HINT","TS_SERVER_DIRECTIVE_HINT" -> 1;
        default -> 90;};}
    private static String hint(String p,String text) {
        if(text.contains("Deno.serve")||text.contains("deno.land/std@")&&text.contains("/http/server"))return "TS_DENO_REGISTRATION_HINT";
        if(p.matches("(?:.*/)?(?:src/)?app/(?:[^/]+/)*route\\.[jt]s")&&HTTP_EXPORT.matcher(text).find())return "TS_NEXT_ROUTE_EXPORT_HINT";
        if(EXPRESS_RUNTIME.matcher(text).find())return "TS_EXPRESS_MODULE_HINT";
        if(text.contains("@supabase/")&&(text.contains("import")||text.contains("require")))return "TS_SUPABASE_CLIENT_MODULE_HINT";
        if(p.matches("(?:.*/)?supabase/functions/[^/]+/index\\.[jt]s"))return "TS_EDGE_FUNCTION_CONVENTION_HINT";
        if(text.stripLeading().startsWith("'use server'")||text.stripLeading().startsWith("\"use server\""))return "TS_SERVER_DIRECTIVE_HINT";
        return "TS_DETERMINISTIC_FALLBACK";
    }
    private static Set<String> references(String p,String text,Map<String,String> specs,Map<String,Map<String,String>> packages) {
        var refs=new TreeSet<String>();var m=IMPORT.matcher(text);
        while(m.find()) {
            String base=Path.of(p).getParent()==null?m.group(1):Path.of(p).getParent().resolve(m.group(1)).toString();
            base=Path.of(base).normalize().toString().replace('\\','/');
            if(base.startsWith("../")||base.startsWith("/"))continue;
            String target=resolveHint(base,specs,packages);if(target!=null)refs.add(target);
        }
        return refs;
    }
    private static String resolveHint(String base,Map<String,String> specs,Map<String,Map<String,String>> packages){
        for(String key:List.of(base,base+".js",base.replaceFirst("\\.js$",".ts"))){String target=specs.get(key);if(target!=null)return target;}
        var metadata=packages.get(Path.of(base).resolve("package.json").normalize().toString().replace('\\','/'));
        if(metadata!=null){
            if(!"PARSED".equals(metadata.get("resolutionStatus"))||"UNKNOWN".equals(metadata.get("mainStatus")))return null;
            if("STATIC".equals(metadata.get("mainStatus"))){
                String main=Path.of(base).resolve(metadata.get("main")).normalize().toString().replace('\\','/');
                if(main.equals("..")||main.startsWith("../")||main.startsWith("/"))return null;
                for(String key:List.of(main,main+".js",Path.of(main).resolve("index").toString().replace('\\','/'))){String target=specs.get(key);if(target!=null)return target;}
            }
        }
        return specs.get(Path.of(base).resolve("index").normalize().toString().replace('\\','/'));
    }
    private static int convention(String p){return p.matches("(?:.*/)?supabase/functions/.*|(?:.*/)?app/(?:[^/]+/)*route\\.[jt]s")?0:1;}
    private static int length(ProjectFile f){long n=f.lines().stream().mapToLong(l->l.length()+1L).sum();return (int)Math.min(n,Integer.MAX_VALUE);}
    private static String prefix(ProjectFile f,int max){var b=new StringBuilder();for(String line:f.lines()){if(b.length()>=max)break;int n=Math.min(line.length(),max-b.length());b.append(line,0,n);if(b.length()<max)b.append('\n');}return b.toString();}
}
