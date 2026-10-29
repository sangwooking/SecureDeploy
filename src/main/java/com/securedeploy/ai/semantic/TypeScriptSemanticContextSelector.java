package com.securedeploy.ai.semantic;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.analysis.typescript.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import org.springframework.stereotype.Component;

/** Worker-registered Express handlers only. Selection does not assert security or runtime reachability. */
@Component
public class TypeScriptSemanticContextSelector {
    public record Source(String path,String content,String originalHash) { }
    private final TypeScriptAnalysisProperties properties;private final SemanticProperties limits;private final SemanticSanitizer sanitizer;
    private final ObjectMapper json=new ObjectMapper();private final Semaphore capacity=new Semaphore(1);
    public TypeScriptSemanticContextSelector(TypeScriptAnalysisProperties properties,SemanticProperties limits,SemanticSanitizer sanitizer){this.properties=properties;this.limits=limits;this.sanitizer=sanitizer;}
    public SecuritySliceCollector.Collection select(ServerAnalysisSnapshot analysis,List<Source> sources){
        var slices=new ArrayList<SecuritySlice>();int omitted=0,total=0;
        if(analysis==null||analysis.nodeUses()==null)return new SecuritySliceCollector.Collection(List.of(),0,List.of("NO_WORKER_REGISTERED_HTTP_CONTEXT"),true);
        for(var entry:analysis.nodeUses()){
            if(!"JS_SERVER_ENTRY_CONTEXT".equals(entry.ruleId())||!"ENTRY_REGISTERED".equals(entry.kind())||!"EXPRESS_ROUTER_MOUNTED".equals(entry.operation())||entry.trace()==null)continue;
            for(var target:entry.trace()){
                if(!"EXPRESS_HANDLER_TARGET".equals(target.kind()))continue;
                var source=sources.stream().filter(s->s.path().equals(target.filePath())).findFirst().orElse(null);
                var coverage=analysis.files()==null?null:analysis.files().stream().filter(f->f.filePath().equals(target.filePath())&&"PARSED".equals(f.parseStatus())&&f.entrypoints()>0&&"PARTIAL".equals(f.flowStatus())).findFirst().orElse(null);
                if(source==null||coverage==null||!safe(source.path())||source.content()==null||source.content().length()>100000)continue;
                var unknown=analysis.nodeUses().stream().filter(n->Set.of("FLOW_UNRESOLVED","UNKNOWN","PROCESS_CONTRACT_UNKNOWN").contains(n.kind())&&n.location()!=null&&n.location().filePath().equals(target.filePath())).map(ServerAnalysisSnapshot.NodeUse::location).limit(100).toList();
                if(unknown.isEmpty())continue;
                if(slices.size()>=limits.getMaxSlices()){omitted++;continue;}
                try{
                    var node=extract(source.content(),target,unknown);String content=node.path("content").asText();int from=node.path("startLine").asInt(),to=node.path("endLine").asInt();
                    if(content.isBlank()||content.length()>limits.getMaxSnippetChars()||from<1||to<from||!content.equals(sanitizer.text(content,limits.getMaxSnippetChars()))||total+content.length()>limits.getMaxContextChars())throw new IllegalArgumentException();
                    String id=SecuritySliceCollector.id(source.path()+":"+from+":"+source.originalHash());
                    if(slices.stream().anyMatch(s->s.sliceId().equals(id)))continue;
                    var linked=analysis.validatedFindings()==null?List.<SecuritySlice.ExistingFinding>of():analysis.validatedFindings().stream().filter(f->f.location().filePath().equals(source.path())&&f.location().line()>=from&&f.location().line()<=to).limit(20).map(f->new SecuritySlice.ExistingFinding(f.findingId(),f.ruleId(),source.path(),f.location().line())).toList();
                    var context=new SecuritySlice.CodeContext(id,source.path(),from,to,target.functionName(),false,content);
                    slices.add(new SecuritySlice(id,"WORKER_REGISTERED_EXPRESS_HANDLER","STATIC_REGISTRATION_ENDPOINT_NOT_TRANSMITTED","UNKNOWN","AUTHORIZATION_NOT_VERIFIED",List.of(),List.of(context),linked,List.of("NODE_FLOW_UNRESOLVED","REDACTED_LITERALS_AND_COMMENTS","DIRECT_HANDLER_ONLY_NO_HELPER_BODY","STATIC_REGISTRATION_NOT_RUNTIME_PROOF")));total+=content.length();
                }catch(RuntimeException e){omitted++;}
            }
        }
        return new SecuritySliceCollector.Collection(List.copyOf(slices),omitted,List.of("BOUNDED_EXPRESS_HANDLER_CONTEXTS_ONLY","OTHER_UNKNOWN_FILES_NOT_REVIEWED","MODEL_CANDIDATE_NOT_CONFIRMED_FINDING"),true);
    }
    private com.fasterxml.jackson.databind.JsonNode extract(String source,ServerAnalysisSnapshot.Location target,List<ServerAnalysisSnapshot.Location> unknown){
        if(!properties.isEnabled()||!capacity.tryAcquire())throw new IllegalArgumentException();Process p=null;var io=Executors.newFixedThreadPool(2);
        try{Path dir=Path.of(properties.getAnalyzerDirectory()).toRealPath();byte[] data=json.writeValueAsBytes(Map.of("source",source,"target",target,"unknowns",unknown,"maxChars",limits.getMaxSnippetChars()));
            var builder=new ProcessBuilder(properties.getNodeExecutable(),"--permission","--no-addons","--max-old-space-size=192","--allow-fs-read="+dir,dir.resolve("semantic-context.mjs").toString());builder.environment().clear();builder.environment().put("LANG","en_US.UTF-8");builder.redirectError(ProcessBuilder.Redirect.DISCARD);p=builder.start();final var child=p;
            var writer=io.submit(()->{try(var out=child.getOutputStream()){out.write(data);}catch(Exception e){throw new IllegalArgumentException();}});
            var reader=io.submit(()->{try(var in=child.getInputStream()){return in.readNBytes(16385);}catch(Exception e){throw new IllegalArgumentException();}});
            if(!p.waitFor(3,TimeUnit.SECONDS))throw new IllegalArgumentException();writer.get(1,TimeUnit.SECONDS);byte[] bytes=reader.get(1,TimeUnit.SECONDS);if(p.exitValue()!=0||bytes.length>16384)throw new IllegalArgumentException();return json.readTree(bytes);
        }catch(InterruptedException e){Thread.currentThread().interrupt();throw new IllegalArgumentException();}catch(Exception e){throw new IllegalArgumentException();}
        finally{if(p!=null&&p.isAlive())p.destroyForcibly();io.shutdownNow();capacity.release();}
    }
    private static boolean safe(String p){return p!=null&&!p.startsWith("/")&&!p.contains("..")&&!p.contains("\\")&&!p.contains("@")&&!p.contains(":")&&p.length()<240;}
}
