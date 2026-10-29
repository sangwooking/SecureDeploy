package com.securedeploy.analysis.typescript;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.project.coverage.CoverageRecorder;
import com.securedeploy.project.model.ProjectFile;
import java.nio.file.Path;
import java.util.*;

/** Untrusted JSON metadata, never shell parsing, script execution or module loading. */
final class NodeManifestMetadata {
    private static final ObjectMapper JSON=new ObjectMapper(JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(32).maxStringLength(100_000).build()).build());
    record Catalog(List<Map<String,String>> worker,List<String> seeds,int characters,boolean complete) { }
    static Catalog read(List<ProjectFile> files) {
        var manifests=new ArrayList<Map<String,String>>();var seeds=new TreeSet<String>();
        int chars=0;boolean complete=true;
        for(var f:files.stream().filter(f->f.relativePath().equals("package.json")||f.relativePath().endsWith("/package.json"))
                .sorted(Comparator.comparing(ProjectFile::relativePath)).toList()) {
            String p=CoverageRecorder.safePath(f.relativePath());
            int size=(int)Math.min(Integer.MAX_VALUE,f.lines().stream().mapToLong(l->l.length()+1L).sum());
            if(p.equals("[redacted-path]")||manifests.size()>=100||size>100_000||chars+size>1_000_000){complete=false;continue;}
            chars+=size;var metadata=new TreeMap<String,String>();metadata.put("filePath",p);
            metadata.put("resolutionStatus","MALFORMED");metadata.put("mainStatus","UNKNOWN");
            try {
                var doc=JSON.readTree(String.join("\n",f.lines()));
                if(doc==null||!doc.isObject())throw new IllegalArgumentException();
                metadata.put("resolutionStatus","PARSED");
                String type=doc.path("type").asText("");
                metadata.put("moduleType",!doc.has("type")||type.equals("commonjs")?"commonjs":type.equals("module")?"module":"unknown");
                var main=doc.get("main");
                if(main==null||main.isNull()||main.isTextual()&&main.asText().isEmpty())metadata.put("mainStatus","ABSENT");
                else if(main.isTextual()&&valid(main.asText())){
                    metadata.put("mainStatus","STATIC");metadata.put("main",main.asText());addSeed(seeds,p,main.asText());
                } else complete=false;
                for(String name:List.of("express","mongodb","next","sequelize","mongoose","validator","cors","express-session","express-rate-limit","@upstash/ratelimit","better-auth")) {
                    var v=doc.path("dependencies").path(name);
                    if(v.isTextual()&&v.asText().length()<=80&&v.asText().matches("[~^]?[0-9]+\\.[0-9]+\\.[0-9]+(?:-[A-Za-z0-9.-]+)?"))metadata.put(name,v.asText());
                }
                var config=doc.path("nodemonConfig");
                String local=p.substring(0,p.length()-"package.json".length())+"nodemon.json";
                var localFiles=files.stream().filter(c->c.relativePath().equals(local)).toList();
                if(!localFiles.isEmpty()) {
                    var c=localFiles.get(0);int n=c.lines().stream().mapToInt(l->l.length()+1).sum();
                    if(localFiles.size()!=1||n>100_000||chars+n>1_000_000){config=null;complete=false;}
                    else {chars+=n;try{config=JSON.readTree(String.join("\n",c.lines()));}catch(Exception ignored){config=null;}}
                }
                var scripts=doc.path("scripts");int bootstrap=0;
                if(scripts.isObject())for(String name:iterable(scripts.fieldNames()).stream().sorted().limit(20).toList()) {
                    if(!name.matches("(?:start|dev|serve)(?::[A-Za-z0-9_-]+)?"))continue;
                    var script=scripts.get(name);if(!script.isTextual())continue;
                    String command=script.asText();
                    String target=bootstrap(command,config,metadata.get("main"));
                    if(target!=null){addSeed(seeds,p,target);metadata.put("bootstrap"+bootstrap++,target);}
                    else metadata.put("bootstrapUnknown","true");
                }
            }catch(Exception ignored){complete=false;metadata.put("resolutionStatus","MALFORMED");metadata.put("mainStatus","UNKNOWN");}
            manifests.add(Map.copyOf(metadata));
        }
        return new Catalog(List.copyOf(manifests),List.copyOf(seeds),chars,complete);
    }
    private static List<String> iterable(Iterator<String> names){var result=new ArrayList<String>();names.forEachRemaining(result::add);return result;}
    // A bounded command grammar, not a shell lexer. No quoting, expansion or wrappers.
    private static String bootstrap(String command,com.fasterxml.jackson.databind.JsonNode config,String main){
        if(command.length()>260||!command.matches("[A-Za-z0-9_./, \\t-]+"))return null;
        String[] words=command.trim().split("[ \\t]+");
        if(words.length==2&&words[0].equals("node"))return validTarget(words[1])?words[1]:null;
        if(!words[0].equals("nodemon"))return null;
        if(config==null||!config.isMissingNode()&&!config.isObject())return null;
        if(config.has("exec")||config.has("execMap")||config.has("cwd")||config.has("events"))return null;
        String target=null;
        for(int i=1;i<words.length;i++){
            String w=words[i];
            if(Set.of("--ignore","--watch","--ext","-e","-w").contains(w)){
                if(++i>=words.length||words[i].startsWith("-"))return null;
            }else if(w.equals("--config")){
                if(++i>=words.length||!words[i].equals("nodemon.json")||config.isMissingNode())return null;
            }else if(!w.startsWith("-")&&target==null&&validTarget(w))target=w;
            else return null;
        }
        if(target==null&&config.path("script").isTextual())target=config.path("script").asText();
        if(target==null)target=main;
        return target!=null&&validTarget(target)?target:null;
    }
    private static boolean validTarget(String p){return valid(p)&&!p.startsWith("-")&&!p.contains("*")&&!p.equals("..");}
    private static boolean valid(String p){return !p.isEmpty()&&p.length()<=240&&p.matches("[A-Za-z0-9_@./-]+")&&!p.startsWith("/");}
    private static void addSeed(Set<String> seeds,String manifest,String relative){
        var dir=Path.of(manifest).getParent();String p=(dir==null?Path.of(relative):dir.resolve(relative)).normalize().toString().replace('\\','/');
        if(!p.equals("..")&&!p.startsWith("../")&&!p.startsWith("/"))seeds.add(p);
    }
}
