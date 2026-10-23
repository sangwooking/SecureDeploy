package com.securedeploy.editing;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.analysis.typescript.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import org.springframework.stereotype.Component;

/** Trusted parse-only validator. Target code is stdin data, never imported or executed. */
@Component
public class ResponsePatchValidator {
    private final TypeScriptAnalysisProperties properties;
    private static final Semaphore CAPACITY=new Semaphore(1);
    private final ObjectMapper mapper=new ObjectMapper();
    public ResponsePatchValidator(TypeScriptAnalysisProperties properties){this.properties=properties;}
    record Contract(String source,ServerAnalysisSnapshot.Location sink,List<ServerAnalysisSnapshot.Location> sources) { }
    record Target(String before,int offset,int line,List<String> removed,String suggestedReplacement) { }
    Target check(Contract contract,String replacement) {
        if(!properties.isEnabled()||!CAPACITY.tryAcquire())throw new IllegalArgumentException();
        Process process=null;var io=Executors.newFixedThreadPool(2,r->{var t=new Thread(r,"response-patch-parser");t.setDaemon(true);return t;});
        try {
            var dir=Path.of(properties.getAnalyzerDirectory()).toRealPath();
            var data=new LinkedHashMap<String,Object>();data.put("source",contract.source());data.put("sink",contract.sink());data.put("sources",contract.sources());
            if(replacement!=null)data.put("replacement",replacement);
            byte[] input=mapper.writeValueAsBytes(data);if(input.length>150000)throw new IllegalArgumentException();
            var builder=new ProcessBuilder(properties.getNodeExecutable(),"--permission","--no-addons","--max-old-space-size=192",
                    "--allow-fs-read="+dir,dir.resolve("response-patch.mjs").toString());
            builder.directory(dir.toFile());builder.environment().clear();builder.environment().put("LANG","en_US.UTF-8");builder.redirectError(ProcessBuilder.Redirect.DISCARD);
            process=builder.start();final var child=process;
            var writer=io.submit(()->{try(var stream=child.getOutputStream()){stream.write(input);}catch(Exception e){throw new IllegalArgumentException();}});
            var reader=io.submit(()->{try(var stream=child.getInputStream()){return stream.readNBytes(16385);}});
            if(!process.waitFor(3,TimeUnit.SECONDS))throw new IllegalArgumentException();
            writer.get(1,TimeUnit.SECONDS);byte[] output=reader.get(1,TimeUnit.SECONDS);
            if(process.exitValue()!=0||output.length>16384)throw new IllegalArgumentException();
            var result=mapper.readValue(output,Target.class);
            if(result.before()==null||result.before().length()>4096||result.offset()<0||result.line()<1||result.removed()==null||result.removed().isEmpty()
                    ||result.suggestedReplacement()==null||result.suggestedReplacement().length()>4096)throw new IllegalArgumentException();
            return result;
        }catch(InterruptedException e){Thread.currentThread().interrupt();throw new IllegalArgumentException();}
        catch(Exception e){throw new IllegalArgumentException();}
        finally{if(process!=null&&process.isAlive()){process.destroyForcibly();try{process.waitFor(2,TimeUnit.SECONDS);}catch(InterruptedException e){Thread.currentThread().interrupt();}}io.shutdownNow();if(process==null||!process.isAlive())CAPACITY.release();}
    }
}
