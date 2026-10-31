package com.securedeploy.editing;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Generates two files with a trusted npm CLI. Project files, npmrc and scripts are never executed. */
@Component
public class NpmTreeExecutor {
    public record Output(byte[] manifest,byte[] lockfile,String npmVersion,String nodeVersion){}
    private final ObjectMapper json;private final String executable;private final Semaphore capacity=new Semaphore(1);
    public NpmTreeExecutor(ObjectMapper json,@Value("${securedeploy.editing.npm-executable:/opt/homebrew/bin/npm}")String executable){this.json=json;this.executable=executable;}
    public Output generate(byte[] manifest,byte[] lockfile,String section,String root,String candidate)throws Exception{
        if(!capacity.tryAcquire())throw new IllegalStateException("NPM_BUSY");Path temp=null;Process child=null;
        try{
            temp=Files.createTempDirectory("securedeploy-tree-plan-");Files.setPosixFilePermissions(temp,java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));Path work=Files.createDirectory(temp.resolve("work"));
            var next=NpmTreePlanner.parse(json,manifest);((ObjectNode)next.path(section)).put(root,candidate);
            Files.write(work.resolve("package.json"),json.writerWithDefaultPrettyPrinter().writeValueAsBytes(next));Files.write(work.resolve("package-lock.json"),lockfile);Files.writeString(temp.resolve("user.npmrc"),"");Files.writeString(temp.resolve("global.npmrc"),"");
            String npm=version(List.of(executable,"--version"),work),node=version(List.of(Path.of(executable).getParent().resolve("node").toString(),"--version"),work);if(!npm.matches("11\\.[0-9]+\\.[0-9]+"))throw new IllegalArgumentException("NPM_11_REQUIRED");
            var command=List.of(executable,"install","--package-lock-only","--ignore-scripts","--no-audit","--no-fund","--strict-peer-deps","--engine-strict","--registry=https://registry.npmjs.org/","--userconfig="+temp.resolve("user.npmrc"),"--globalconfig="+temp.resolve("global.npmrc"),"--cache="+temp.resolve("cache"));
            child=builder(command,work).redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(60);
            while(!child.waitFor(100,TimeUnit.MILLISECONDS)){if(System.nanoTime()>end)throw new IllegalStateException("NPM_TIMEOUT");quota(temp);}quota(temp);if(child.exitValue()!=0)throw new IllegalArgumentException("NPM_PEER_ENGINE_OR_RESOLUTION_FAILURE");
            try(var files=Files.list(work)){if(files.count()!=2)throw new IllegalArgumentException("UNEXPECTED_NPM_FILE");}
            if(Files.size(work.resolve("package.json"))>SourceArchive.EDIT_BYTES||Files.size(work.resolve("package-lock.json"))>SourceArchive.EDIT_BYTES)throw new IllegalArgumentException("EDIT_SIZE_LIMIT");
            return new Output(Files.readAllBytes(work.resolve("package.json")),Files.readAllBytes(work.resolve("package-lock.json")),npm,node);
        }finally{if(child!=null&&child.isAlive()){child.destroyForcibly();child.waitFor(3,TimeUnit.SECONDS);}try{if(temp!=null)try(var files=Files.walk(temp)){for(Path p:files.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}finally{capacity.release();}}
    }
    private ProcessBuilder builder(List<String> args,Path work){var p=new ProcessBuilder(args).directory(work.toFile());p.environment().clear();p.environment().put("PATH",Path.of(executable).getParent()+":/usr/bin:/bin");p.environment().put("LANG","en_US.UTF-8");return p;}
    private String version(List<String> args,Path work)throws Exception{var p=builder(args,work).redirectError(ProcessBuilder.Redirect.DISCARD).start();try{if(!p.waitFor(5,TimeUnit.SECONDS)||p.exitValue()!=0)throw new IllegalArgumentException("NPM_TOOL_VERSION");return new String(p.getInputStream().readNBytes(128),java.nio.charset.StandardCharsets.UTF_8).trim();}finally{if(p.isAlive())p.destroyForcibly();}}
    private void quota(Path root)throws Exception{try(var files=Files.walk(root)){var paths=files.limit(3001).toList();if(paths.size()>3000)throw new IllegalStateException("NPM_FILE_LIMIT");long n=0;for(Path p:paths)if(Files.isRegularFile(p))n+=Files.size(p);if(n>96L*1024*1024)throw new IllegalStateException("NPM_DISK_LIMIT");}}
}
