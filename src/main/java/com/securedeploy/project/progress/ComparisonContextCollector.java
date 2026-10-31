package com.securedeploy.project.progress;

import com.securedeploy.project.model.ProjectStructure;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.stereotype.Component;

@Component
public class ComparisonContextCollector {
    private final String version = analyzerVersion();

    private final com.securedeploy.analysis.typescript.TypeScriptAnalysisProperties ts;
    private final com.securedeploy.analysis.python.PythonAnalysisProperties py;
    public ComparisonContextCollector(){this(new com.securedeploy.analysis.typescript.TypeScriptAnalysisProperties(),new com.securedeploy.analysis.python.PythonAnalysisProperties());}
    @org.springframework.beans.factory.annotation.Autowired
    public ComparisonContextCollector(com.securedeploy.analysis.typescript.TypeScriptAnalysisProperties ts,com.securedeploy.analysis.python.PythonAnalysisProperties py){this.ts=ts;this.py=py;}
    public ComparisonContext collect(ProjectStructure structure){return collect(structure,null);}
    public ComparisonContext collect(ProjectStructure structure,com.securedeploy.analysis.typescript.ServerAnalysisSnapshot server) {
        var hashes=new java.util.TreeMap<String,String>();boolean complete=true;long total=0;
        for(var file:structure.analysisFiles())try{
            if(hashes.size()>=10000||java.nio.file.Files.isSymbolicLink(file.absolutePath())){complete=false;break;}
            long size=java.nio.file.Files.size(file.absolutePath());total+=size;
            if(size>25_000_000||total>100_000_000){complete=false;break;}
            byte[] bytes=java.nio.file.Files.readAllBytes(file.absolutePath());
            try{var text=java.nio.charset.StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(bytes)).toString();
                if(!text.lines().toList().equals(file.lines())){complete=false;continue;}
                if(hashes.putIfAbsent(normalize(file.relativePath()),HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)))!=null)complete=false;
            }finally{java.util.Arrays.fill(bytes,(byte)0);}
        }catch(Exception unavailable){complete=false;}
        var engines=new java.util.TreeMap<String,String>();engines.put("backend",java.util.Objects.toString(version,"UNKNOWN"));
        engines.put("typescript",server==null?"UNKNOWN":java.util.Objects.toString(server.analyzerVersion(),"UNKNOWN"));
        engines.put("python",server==null||server.pythonAnalysis()==null?"UNKNOWN":java.util.Objects.toString(server.pythonAnalysis().analyzerVersion(),"UNKNOWN"));
        engines.put("typescriptConfiguration",ts.isEnabled()+":"+ts.getTimeoutSeconds());engines.put("pythonConfiguration",py.isEnabled()+":"+py.getTimeoutSeconds());
        engines.put("typescriptParser",server==null?"UNKNOWN":java.util.Objects.toString(server.parserVersion(),"NOT_EXECUTED"));
        engines.put("pythonParser",server==null||server.pythonAnalysis()==null?"UNKNOWN":java.util.Objects.toString(server.pythonAnalysis().parserVersion(),"NOT_EXECUTED"));
        engines.put("typescriptArtifact",artifact(ts.getAnalyzerDirectory(),".mjs"));
        engines.put("pythonArtifact",artifact(py.getAnalyzerDirectory(),".py"));
        return new ComparisonContext(1,null,version,true,structure.analysisFiles().stream().map(f->normalize(f.relativePath())).distinct().sorted().toList(),null,
            new ComparisonEvidence(1,"SHA256_BYTES_V1",hashes,complete,engines,anchorHashes(structure,server)));
    }
    private static java.util.Map<String,String> anchorHashes(ProjectStructure structure,com.securedeploy.analysis.typescript.ServerAnalysisSnapshot server){
        var out=new java.util.TreeMap<String,String>();if(server==null)return out;
        var locations=new java.util.ArrayList<com.securedeploy.analysis.typescript.ServerAnalysisSnapshot.Location>();
        for(var analysis:java.util.stream.Stream.of(server,server.pythonAnalysis()).filter(java.util.Objects::nonNull).toList()){
            analysis.findings().forEach(f->{locations.add(f.source());locations.add(f.sink());});
            analysis.authorizationContexts().forEach(c->locations.add(c.entry()));
        }
        var sources=structure.analysisFiles().stream().collect(java.util.stream.Collectors.toMap(f->normalize(f.relativePath()),f->f,(a,b)->a));
        for(var at:locations){if(out.size()>=2000)break;var file=sources.get(normalize(at.filePath()));if(file==null||at.line()<1||at.line()>file.lines().size())continue;
            try{out.put(normalize(at.filePath())+"#"+at.line(),HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(file.lines().get(at.line()-1).getBytes(java.nio.charset.StandardCharsets.UTF_8))));}catch(Exception unavailable){return java.util.Map.of();}}
        return out;
    }
    private static String digestFile(java.nio.file.Path path)throws Exception{
        var d=MessageDigest.getInstance("SHA-256");try(var in=java.nio.file.Files.newInputStream(path)){var b=new byte[65536];int n;while((n=in.read(b))!=-1)d.update(b,0,n);}return HexFormat.of().formatHex(d.digest());
    }
    private static String artifact(String directory,String suffix){
        try(var paths=java.nio.file.Files.list(java.nio.file.Path.of(directory))){
            var d=MessageDigest.getInstance("SHA-256");var files=paths.filter(p->p.getFileName().toString().endsWith(suffix)||p.getFileName().toString().equals("package-lock.json")).sorted().limit(257).toList();
            if(files.isEmpty()||files.size()>256)return "UNKNOWN";long size=0;
            for(var p:files){if(java.nio.file.Files.isSymbolicLink(p)||(size+=java.nio.file.Files.size(p))>10_000_000)return "UNKNOWN";d.update(p.getFileName().toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));d.update(digestFile(p).getBytes(java.nio.charset.StandardCharsets.UTF_8));}
            return HexFormat.of().formatHex(d.digest());
        }catch(Exception unavailable){return "UNKNOWN";}
    }

    static String normalize(String path) {
        String value = path == null ? "" : path.replace('\\', '/');
        while (value.startsWith("./")) value = value.substring(2);
        return value;
    }

    private static String analyzerVersion() {
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            var resolver = new PathMatchingResourcePatternResolver();
            for (String area : new String[] {"rule", "dependency", "project/service", "project/coverage", "sca/parser", "sca/client", "sca/service", "analysis/python", "analysis/deployment", "analysis/javaflow", "analysis/typescript"}) {
                var resources = resolver.getResources("classpath*:com/securedeploy/" + area + "/**/*.class");
                java.util.Arrays.sort(resources, java.util.Comparator.comparing(r -> r.getDescription()));
                for (var resource : resources) {
                    try (var input = resource.getInputStream()) { digest.update(input.readAllBytes()); }
                }
            }
            return "coverage-v2:" + HexFormat.of().formatHex(digest.digest());
        } catch (Exception failure) {
            // Unknown analyzer versions cannot establish negative evidence.
            return null;
        }
    }
}
