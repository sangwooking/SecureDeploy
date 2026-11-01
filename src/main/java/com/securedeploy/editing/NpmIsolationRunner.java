package com.securedeploy.editing;

import com.fasterxml.jackson.databind.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/** Local Docker control is trusted. The guest receives stdin data only: no mounts, sockets, secrets or network. */
@Component
public class NpmIsolationRunner {
    public record Output(byte[] manifest,byte[] lockfile,String npmVersion,String nodeVersion,String jobId,int attempts) { }
    private final ObjectMapper json;private final NpmRegistry registry;private final String docker,socket,image,script;
    private final Path config;private volatile boolean ready;private final Set<String> active=ConcurrentHashMap.newKeySet();private final Semaphore capacity=new Semaphore(1);
    public NpmIsolationRunner(ObjectMapper json,NpmRegistry registry,Environment env) {
        this.json=json;this.registry=registry;
        docker=env.getProperty("securedeploy.editing.npm-isolation.docker-executable","/opt/homebrew/bin/docker");
        socket=env.getProperty("securedeploy.editing.npm-isolation.socket",System.getProperty("user.home")+"/.docker/run/docker.sock");
        image=env.getProperty("securedeploy.editing.npm-isolation.image","");Path privateConfig=null;String source="";
        if(env.getProperty("securedeploy.editing.npm-isolation.enabled",Boolean.class,false))try{
            if(!validImage(image)||!Path.of(docker).isAbsolute()||!Path.of(socket).isAbsolute()||Files.isSymbolicLink(Path.of(socket))
                    ||!Files.getOwner(Path.of(socket)).getName().equals(System.getProperty("user.name")))throw new IllegalArgumentException();
            privateConfig=Files.createTempDirectory("securedeploy-docker-config-");Files.setPosixFilePermissions(privateConfig,java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
            try(var input=getClass().getResourceAsStream("/npm-isolation-runner.mjs")){if(input==null)throw new IllegalArgumentException();source=new String(input.readNBytes(32769),StandardCharsets.UTF_8);if(source.length()>32768)throw new IllegalArgumentException();}
        }catch(Exception unavailable){privateConfig=null;}
        config=privateConfig;script=source;
        if(config!=null)try{
            var inspection=run(List.of("image","inspect",image,"--format","{{json .RepoDigests}}"),null,5,8192);
            var digests=json.readTree(inspection);boolean match=false;for(var digest:digests)if(digest.asText().equals(image)||digest.asText().equals("docker.io/library/"+image))match=true;
            var info=json.readTree(run(List.of("info","--format","{{json .}}"),null,5,262144));
            ready=match&&info.path("OSType").asText().equals("linux")&&info.path("CgroupVersion").asText().equals("2")
                    &&info.path("SecurityOptions").toString().contains("seccomp");
            if(ready){String name="securedeploy-npm-"+UUID.randomUUID();try{
                String preflight=script.substring(0,script.indexOf("// BEGIN_INPUT"))+"console.log('NPM_ISOLATION_READY');";
                ready=new String(run(containerArgs(name,preflight),null,8,1024),StandardCharsets.UTF_8).trim().equals("NPM_ISOLATION_READY");
            }finally{cleanup(name);}}
        }catch(Exception unavailable){ready=false;}
    }
    public boolean available(){return ready;}
    static boolean validImage(String image){return image!=null&&image.matches("node@sha256:[a-f0-9]{64}");}
    static String packageFromMiss(String name){if(name==null||name.length()>214||name.contains("..")||!name.matches("(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+"))throw new IllegalArgumentException("NPM_BROKER_NAME");return name;}
    List<String> containerArgs(String name,String code){
        if(!name.matches("securedeploy-npm-[a-f0-9-]{36}"))throw new IllegalArgumentException();
        return List.of("run","--rm","--pull=never","--name="+name,"--interactive","--init","--network=none","--read-only",
                "--cap-drop=ALL","--security-opt=no-new-privileges","--user=65532:65532","--memory=512m","--memory-swap=512m","--cpus=1","--pids-limit=32",
                "--ulimit=nofile=64:64","--ulimit=fsize=41943040:41943040",
                "--tmpfs=/work:rw,noexec,nosuid,nodev,size=16m,uid=65532,gid=65532",
                "--tmpfs=/cache:rw,noexec,nosuid,nodev,size=64m,uid=65532,gid=65532",
                "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=8m,uid=65532,gid=65532",
                "--entrypoint=/usr/bin/timeout",image,"--signal=KILL","28s","/usr/local/bin/node","--input-type=module","--eval",code);
    }
    public Output generate(byte[] manifest,byte[] lockfile)throws Exception {
        if(!available())throw new IllegalStateException("NPM_ISOLATION_UNAVAILABLE");
        if(!capacity.tryAcquire())throw new IllegalStateException("NPM_BUSY");
        long metadataBudget=1024+6L*(manifest.length+lockfile.length);
        String job=UUID.randomUUID().toString();var metadata=new ArrayList<Map<String,String>>();var seen=new HashSet<String>();long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(100);
        try{
            for(int attempt=1;attempt<=24;attempt++){
                if(System.nanoTime()>deadline)throw new IllegalStateException("NPM_ISOLATION_TIMEOUT");
                byte[] input=json.writeValueAsBytes(Map.of("manifest",new String(manifest,StandardCharsets.UTF_8),"lockfile",new String(lockfile,StandardCharsets.UTF_8),"metadata",metadata));
                if(input.length>48*1024*1024)throw new IllegalArgumentException("NPM_METADATA_BUDGET");
                String name="securedeploy-npm-"+job;active.add(name);JsonNode result;
                try{result=json.readTree(run(containerArgs(name,script),input,Math.max(1,Math.min(30,(int)Math.ceil((deadline-System.nanoTime())/1e9))),1048576));}
                finally{Arrays.fill(input,(byte)0);cleanup(name);}
                if(result.path("status").asText().equals("SUCCESS")){
                    var files=result.path("files");if(!files.isObject()||files.size()!=2||!files.has("package.json")||!files.has("package-lock.json"))throw new IllegalArgumentException("NPM_OUTPUT_FILES");
                    byte[] m=Base64.getDecoder().decode(files.path("package.json").asText()),l=Base64.getDecoder().decode(files.path("package-lock.json").asText());
                    if(m.length>SourceArchive.EDIT_BYTES||l.length>SourceArchive.EDIT_BYTES||!result.path("npmVersion").asText().matches("11\\.[0-9]+\\.[0-9]+"))throw new IllegalArgumentException("NPM_OUTPUT_LIMIT");
                    return new Output(m,l,result.path("npmVersion").asText(),result.path("nodeVersion").asText(),job,attempt);
                }
                if(result.path("reason").asText().equals("RESOURCE_LIMIT"))throw new IllegalStateException("NPM_ISOLATION_RESOURCE_LIMIT");
                if(!result.path("status").asText().equals("CACHE_MISS"))throw new IllegalArgumentException("NPM_OFFLINE_OR_POLICY_REJECTED");
                if(!result.path("missing").isArray()||result.path("missing").size()>24)throw new IllegalArgumentException("NPM_BROKER_FORMAT");
                int fresh=0;
                for(var value:result.path("missing")){
                    String missing=packageFromMiss(value.asText());if(!seen.add(missing))continue;
                    if(seen.size()>64||System.nanoTime()>deadline)throw new IllegalArgumentException("NPM_METADATA_BUDGET");
                    String body=registry.packument(missing);long cost=jsonStringBudget(body)+missing.length()+64;
                    if(cost>48L*1024*1024-metadataBudget)throw new IllegalArgumentException("NPM_METADATA_BUDGET");
                    metadataBudget+=cost;metadata.add(Map.of("name",missing,"body",body));fresh++;
                }
                if(fresh==0)throw new IllegalArgumentException("NPM_OFFLINE_CACHE_CONTRACT");
            }
            throw new IllegalArgumentException("NPM_METADATA_COUNT_LIMIT");
        }finally{capacity.release();}
    }
    static long jsonStringBudget(String text){
        long bytes=2;for(int i=0;i<text.length();i++){char c=text.charAt(i);bytes+=c<32?6:c==34||c==92?2:c<128?1:6;}return bytes;
    }
    void cleanup(String name)throws Exception {
        try{run(List.of("rm","--force",name),null,5,1024);}
        catch(Exception cleanup){try{if(run(List.of("ps","--all","--quiet","--filter","name=^/"+name+"$"),null,5,1024).length!=0)throw cleanup;}
            catch(Exception live){ready=false;throw new IllegalStateException("NPM_ISOLATION_CLEANUP_FAILED");}}
        active.remove(name);
    }
    byte[] run(List<String> arguments,byte[] input,int seconds,int maxOutput)throws Exception {
        var command=new ArrayList<String>();command.add(docker);command.add("--host=unix://"+socket);command.add("--config="+config);command.addAll(arguments);
        var builder=new ProcessBuilder(command);builder.environment().clear();builder.environment().put("LANG","en_US.UTF-8");builder.redirectError(ProcessBuilder.Redirect.DISCARD);
        Process child=builder.start();var pool=Executors.newFixedThreadPool(2,r->{var t=new Thread(r,"isolated-npm-io");t.setDaemon(true);return t;});
        try{
            var writer=pool.submit(()->{try(var out=child.getOutputStream()){if(input!=null)out.write(input);}return null;});
            var reader=pool.submit(()->{try(var in=child.getInputStream()){return in.readNBytes(maxOutput+1);}});
            if(!child.waitFor(seconds,TimeUnit.SECONDS))throw new IllegalStateException("NPM_ISOLATION_TIMEOUT");
            writer.get(2,TimeUnit.SECONDS);var bytes=reader.get(2,TimeUnit.SECONDS);if(child.exitValue()>=125&&child.exitValue()<=127)ready=false;if(child.exitValue()!=0||bytes.length>maxOutput)throw new IllegalStateException("NPM_ISOLATION_PROCESS_FAILED");return bytes;
        }finally{if(child.isAlive()){child.destroyForcibly();child.waitFor(2,TimeUnit.SECONDS);}pool.shutdownNow();}
    }
    @jakarta.annotation.PreDestroy public void close(){ready=false;for(String name:List.copyOf(active))try{cleanup(name);}catch(Exception ignored){}if(config!=null)try{try(var files=Files.walk(config)){for(var file:files.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(file);}}catch(Exception ignored){}}
}
