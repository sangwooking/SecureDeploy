package com.securedeploy.editing;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
/** Only the opt-in verified offline container adapter can generate files. Never host npm. */
@Component
public class NpmTreeExecutor {
    public record Output(byte[] manifest,byte[] lockfile,String npmVersion,String nodeVersion,String executionId){
        public Output(byte[] manifest,byte[] lockfile,String npmVersion,String nodeVersion){this(manifest,lockfile,npmVersion,nodeVersion,null);}
    }
    private final ObjectMapper json;private final NpmIsolationRunner isolation;
    public NpmTreeExecutor(ObjectMapper json,String executable){this.json=json;this.isolation=null;}
    @org.springframework.beans.factory.annotation.Autowired
    public NpmTreeExecutor(ObjectMapper json,@Value("${securedeploy.editing.npm-executable:/opt/homebrew/bin/npm}")String ignored,NpmIsolationRunner isolation){this.json=json;this.isolation=isolation;}
    public boolean available(){return isolation!=null&&isolation.available();}
    public Output generate(byte[] manifest,byte[] lockfile,String section,String root,String candidate)throws Exception{
        if(!available())throw new IllegalStateException("NPM_ISOLATION_UNAVAILABLE");
        var before=NpmTreePlanner.read(json,manifest,lockfile);
        if(!java.util.Set.of("dependencies","devDependencies").contains(section)||!before.manifest().path(section).has(root)||!candidate.matches("[0-9]+\\.[0-9]+\\.[0-9]+"))throw new IllegalArgumentException("NPM_SCOPE");
        var next=before.manifest().deepCopy();((ObjectNode)next.path(section)).put(root,candidate);
        var output=isolation.generate(json.writerWithDefaultPrettyPrinter().writeValueAsBytes(next),lockfile);
        return new Output(output.manifest(),output.lockfile(),output.npmVersion(),output.nodeVersion(),output.jobId());
    }
}
