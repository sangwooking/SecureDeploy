package com.securedeploy.editing;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Narrow public-registry leaf dependency contract. Never executes project scripts or accepts model lockfile text. */
@Component
public class NpmUpdateGenerator {
    public record Result(byte[] manifest,byte[] lockfile,List<String> changedPackages) { }
    private final ObjectMapper json;
    public NpmUpdateGenerator(ObjectMapper json,@Value("${securedeploy.editing.npm-generation-enabled:false}") boolean enabled,@Value("${securedeploy.editing.npm-executable:/opt/homebrew/bin/npm}") String executable){this.json=json;}
    // Flags cannot enable the former host runner. Re-enable only with a separately verified isolation adapter.
    public boolean enabled(){return false;}
    public Result generate(byte[] manifest,byte[] lockfile,String name,String current,String candidate,boolean direct)throws Exception {
        throw new IllegalStateException("NPM_ISOLATION_UNAVAILABLE");
    }
    void validateInput(JsonNode m,JsonNode lock,String name,String current,String candidate){
        if(!name.matches("(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+")||name.length()>214||!current.matches("[0-9]+\\.[0-9]+\\.[0-9]+")||!candidate.matches("[0-9]+\\.[0-9]+\\.[0-9]+")||current.length()>64||candidate.length()>64||current.equals(candidate)||!current.split("\\.")[0].equals(candidate.split("\\.")[0])||(current.startsWith("0.")&&!current.split("\\.")[1].equals(candidate.split("\\.")[1])))throw new IllegalArgumentException();
        if(m.has("packageManager")||m.has("workspaces")||m.has("overrides")||m.has("resolutions")||lock.path("lockfileVersion").asInt()!=3||!lock.path("packages").isObject()||!lock.path("packages").path("").isObject()||lock.path("packages").size()>500)throw new IllegalArgumentException("NPM_V3_SINGLE_ROOT_REQUIRED");
        for(String section:List.of("dependencies","devDependencies","optionalDependencies","peerDependencies")){
            if(!Objects.equals(m.get(section),lock.path("packages").path("").get(section)))throw new IllegalArgumentException("MANIFEST_LOCK_ROOT_MISMATCH");
            for(var it=m.path(section).fields();it.hasNext();){var field=it.next();if(!field.getKey().matches("(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+")||field.getKey().contains(".."))throw new IllegalArgumentException("INVALID_PACKAGE_NAME");var spec=field.getValue();if(!spec.isTextual()||!spec.asText().matches("[A-Za-z0-9.*~^<>=| ,+-]+"))throw new IllegalArgumentException("PUBLIC_SEMVER_REQUIRED");}
        }
        boolean found=false;for(var it=lock.path("packages").fields();it.hasNext();){var row=it.next();String p=row.getKey();var v=row.getValue();
            if(p.contains("..")||p.contains("\\")||p.contains(":")||p.contains("%")||!p.isEmpty()&&!p.startsWith("node_modules/")||v.path("link").asBoolean()||v.has("resolved")&&!publicUrl(v.path("resolved").asText()))throw new IllegalArgumentException("REGISTRY_ONLY_NO_WORKSPACE_LINKS");
            for(String section:List.of("dependencies","devDependencies","optionalDependencies","peerDependencies"))for(var specs=v.path(section).fields();specs.hasNext();){var spec=specs.next();if(!spec.getKey().matches("(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+")||spec.getKey().contains("..")||!spec.getValue().isTextual()||!spec.getValue().asText().matches("[A-Za-z0-9.*~^<>=| ,+-]+"))throw new IllegalArgumentException("PUBLIC_SEMVER_REQUIRED");}
            if(p.endsWith("node_modules/"+name)&&v.path("version").asText().equals(current)){found=true;if(v.has("dependencies")&&!v.path("dependencies").isEmpty()||v.has("optionalDependencies")&&!v.path("optionalDependencies").isEmpty())throw new IllegalArgumentException("LEAF_ONLY");}
        }if(!found)throw new IllegalArgumentException("LOCKED_PACKAGE_NOT_FOUND");
    }
    Result validateOutput(byte[] beforeManifest,byte[] beforeLock,byte[] afterManifest,byte[] afterLock,String name,String current,String candidate,boolean direct,String integrity,String tarball)throws Exception {
        var old=read(beforeManifest);var oldLock=read(beforeLock);validateInput(old,oldLock,name,current,candidate);var next=read(afterManifest);var nextLock=read(afterLock);
        var expected=old.deepCopy();if(direct){for(String s:List.of("dependencies","devDependencies"))if(expected.path(s).has(name))((ObjectNode)expected.path(s)).put(name,candidate);}else ((ObjectNode)expected).putObject("overrides").put(name+"@"+current,candidate);
        if(!next.equals(expected)||nextLock.path("lockfileVersion").asInt()!=3)throw new IllegalArgumentException("MANIFEST_SCOPE_CHANGED");
        var oldOuter=oldLock.deepCopy();((ObjectNode)oldOuter).remove("packages");var newOuter=nextLock.deepCopy();((ObjectNode)newOuter).remove("packages");if(!oldOuter.equals(newOuter))throw new IllegalArgumentException("LOCK_METADATA_CHANGED");
        var keys=new HashSet<String>();oldLock.path("packages").fieldNames().forEachRemaining(keys::add);nextLock.path("packages").fieldNames().forEachRemaining(keys::add);var changed=new ArrayList<String>();
        for(String p:keys){var a=oldLock.path("packages").get(p);var b=nextLock.path("packages").get(p);if(Objects.equals(a,b))continue;
            if(p.isEmpty()&&direct){var root=a.deepCopy();for(String s:List.of("dependencies","devDependencies"))if(root.path(s).has(name))((ObjectNode)root.path(s)).put(name,candidate);if(!root.equals(b))throw new IllegalArgumentException();continue;}
            if(a==null||b==null||!p.endsWith("node_modules/"+name)||a!=null&&!a.path("version").asText().equals(current)||b!=null&&(!b.path("version").asText().equals(candidate)||!b.path("integrity").asText().equals(integrity)||!b.path("resolved").asText().equals(tarball)))throw new IllegalArgumentException("UNEXPECTED_DEPENDENCY_GRAPH_CHANGE");
            if(b!=null){var check=b.deepCopy();for(String field:List.of("version","integrity","resolved"))((ObjectNode)check).remove(field);var previous=a==null?json.createObjectNode():a.deepCopy();for(String field:List.of("version","integrity","resolved"))((ObjectNode)previous).remove(field);if(!check.equals(previous))throw new IllegalArgumentException("PACKAGE_CONTRACT_CHANGED");}
            changed.add(p);
        }
        // Check every installed path by package identity, including entries without a resolved URL.
        // A new safe direct version is not proof that an unchanged nested vulnerable copy was fixed.
        for(var it=nextLock.path("packages").fields();it.hasNext();){var row=it.next();if(row.getKey().endsWith("node_modules/"+name)&&row.getValue().path("version").asText().equals(current))throw new IllegalArgumentException("TARGET_VERSION_REMAINS");}
        if(changed.isEmpty())throw new IllegalArgumentException("NO_CHANGE");
        return new Result(afterManifest.clone(),afterLock.clone(),List.copyOf(changed));
    }
    private JsonNode read(byte[] bytes)throws Exception{if(bytes.length>SourceArchive.EDIT_BYTES||SourceArchive.text(bytes)==null)throw new IllegalArgumentException();String text=new String(bytes,StandardCharsets.UTF_8);if(text.contains("\r")||text.startsWith("\ufeff"))throw new IllegalArgumentException("UTF8_LF_REQUIRED");var node=json.reader().with(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION).with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).readTree(bytes);if(!node.isObject())throw new IllegalArgumentException();return node;}
    private static boolean publicUrl(String u){try{var uri=URI.create(u);return "https".equals(uri.getScheme())&&"registry.npmjs.org".equals(uri.getHost())&&uri.getUserInfo()==null&&uri.getPort()==-1&&uri.getRawQuery()==null&&uri.getRawFragment()==null;}catch(Exception e){return false;}}
}
