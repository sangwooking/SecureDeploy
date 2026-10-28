package com.securedeploy.analysis.typescript;

import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.databind.*;
import com.securedeploy.project.model.ProjectFile;
import java.nio.file.Path;
import java.util.*;

/** Supplied bounded JSONC only. Scheduling hints, never runtime resolution proof. */
final class TypeScriptSelectionAliases {
    private static final ObjectMapper JSON=new ObjectMapper(JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(JsonReadFeature.ALLOW_JAVA_COMMENTS,JsonReadFeature.ALLOW_TRAILING_COMMA)
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(32).maxStringLength(64_000).build()).build());
    record Mapping(String pattern,String target) { }
    record Config(String base,boolean ordered,List<Mapping> mappings) { }
    record Hint(String base,boolean ordered) { }
    private final Map<String,Config> configs=new HashMap<>();
    TypeScriptSelectionAliases(List<ProjectFile> files){
        for(var f:files)if(f.relativePath().equals("tsconfig.json")||f.relativePath().endsWith("/tsconfig.json"))configs.put(f.relativePath(),null);
        for(var f:TypeScriptConfigMetadata.read(files))if("SELECTED".equals(f.get("status")))try{
            var doc=JSON.readTree(f.get("content"));
            if(doc==null||!doc.isObject()||doc.has("extends"))continue;
            var options=doc.get("compilerOptions");if(options==null)options=JSON.createObjectNode();
            if(!options.isObject())continue;
            var paths=options.get("paths");if(paths==null)paths=JSON.createObjectNode();
            if(!paths.isObject()||paths.size()>100)continue;
            var base=options.get("baseUrl");if(base!=null&&(!base.isTextual()||!safe(base.asText())))continue;
            String mode=options.path("moduleResolution").asText("legacy").toLowerCase(Locale.ROOT);
            if(!List.of("legacy","bundler","node","node10").contains(mode))continue;
            String dir=parent(f.get("filePath")),root=normalize(dir,base==null?".":base.asText());
            if(root==null)continue;
            var mappings=new ArrayList<Mapping>();boolean valid=true;
            for(var it=paths.fields();it.hasNext();){
                var p=it.next();var targets=p.getValue();String pattern=p.getKey();
                if(!safe(pattern)||stars(pattern)>1){valid=false;break;}
                String target=targets.isArray()&&targets.size()==1&&targets.get(0).isTextual()?targets.get(0).asText():null;
                if(target!=null&&(!safe(target)||stars(target)>1||stars(target)>stars(pattern)))target=null;
                mappings.add(new Mapping(pattern,target));
            }
            if(valid)configs.put(f.get("filePath"),new Config(root,mode.equals("bundler"),List.copyOf(mappings)));
        }catch(Exception ignored){/* Unknown nearest config must not inherit root aliases. */}
    }
    Hint target(String file,String spec){
        String dir=parent(file);Config config=null;
        for(int depth=0;depth<100;depth++){
            String key=dir.isEmpty()?"tsconfig.json":dir+"/tsconfig.json";
            if(configs.containsKey(key)){config=configs.get(key);break;}
            if(dir.isEmpty())break;dir=parent(dir);
        }
        if(config==null||!safe(spec))return null;
        var matches=new ArrayList<Mapping>();
        for(var m:config.mappings()){
            int star=m.pattern().indexOf('*');
            if(star<0?m.pattern().equals(spec):spec.length()>=m.pattern().length()-1&&spec.startsWith(m.pattern().substring(0,star))&&spec.endsWith(m.pattern().substring(star+1)))matches.add(m);
        }
        matches.sort(Comparator.comparingInt((Mapping m)->m.pattern().contains("*")?1:0).thenComparing(Comparator.comparingInt((Mapping m)->prefixLength(m.pattern())).reversed()));
        if(matches.isEmpty())return null;
        var first=matches.get(0);if(first.target()==null)return null;
        if(matches.size()>1&&first.pattern().contains("*")&&matches.get(1).pattern().contains("*")&&prefixLength(first.pattern())==prefixLength(matches.get(1).pattern()))return null;
        int star=first.pattern().indexOf('*');String wild=star<0?"":spec.substring(star,spec.length()-(first.pattern().length()-star-1));
        String base=normalize(config.base(),first.target().replace("*",wild));
        return base==null?null:new Hint(base,config.ordered());
    }
    private static int prefixLength(String s){int p=s.indexOf('*');return p<0?s.length():p;}
    private static long stars(String s){return s.chars().filter(c->c=='*').count();}
    private static boolean safe(String s){return !s.isEmpty()&&s.length()<=240&&!s.contains("\\")&&!s.contains("\0")&&!s.startsWith("/")&&!s.contains(":");}
    private static String normalize(String dir,String target){
        try{String p=Path.of(dir).resolve(target).normalize().toString().replace('\\','/');return p.equals("..")||p.startsWith("../")||p.startsWith("/")?null:p;}catch(RuntimeException e){return null;}
    }
    private static String parent(String p){int at=p.lastIndexOf('/');return at<0?"":p.substring(0,at);}
}
