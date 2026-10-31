package com.securedeploy.editing;

import com.fasterxml.jackson.databind.*;
import com.securedeploy.project.model.*;
import com.securedeploy.sca.model.*;
import com.securedeploy.sca.parser.NpmManifestParser;
import java.nio.file.Path;
import java.math.BigInteger;
import java.util.*;

/** Conservative single-root npm-v3 graph contract. Installation paths are not runtime reachability. */
final class NpmTreePlanner {
    static final List<String> SECTIONS=List.of("dependencies","devDependencies","optionalDependencies","peerDependencies");
    record Input(JsonNode manifest,JsonNode lock,List<DependencyComponent> components){}
    record Target(String name,String version,String root,String rootVersion,String section,String declaredRange,List<String> paths,List<List<DependencyContext.Hop>> chains){}
    static int compare(String a,String b){String[] x=a.split("\\."),y=b.split("\\.");for(int i=0;i<3;i++){int c=new BigInteger(x[i]).compareTo(new BigInteger(y[i]));if(c!=0)return c;}return 0;}
    static boolean upgrade(String a,String b){return a!=null&&b!=null&&a.matches("[0-9]{1,9}\\.[0-9]{1,9}\\.[0-9]{1,9}")&&b.matches("[0-9]{1,9}\\.[0-9]{1,9}\\.[0-9]{1,9}")&&a.split("\\.")[0].equals(b.split("\\.")[0])&&(!a.startsWith("0.")||a.split("\\.")[1].equals(b.split("\\.")[1]))&&compare(a,b)<0;}
    static Input read(ObjectMapper json,byte[] manifest,byte[] lockfile)throws Exception{
        JsonNode m=parse(json,manifest),l=parse(json,lockfile);if(m.has("workspaces")||m.has("packageManager")||m.has("overrides")||m.has("resolutions")||l.path("lockfileVersion").asInt()!=3||!l.path("packages").isObject()||l.path("packages").size()>500)throw new IllegalArgumentException("NPM_V3_SINGLE_ROOT_NO_EXISTING_OVERRIDES");
        var packages=l.path("packages");if(!packages.path("").isObject())throw new IllegalArgumentException("LOCK_ROOT_MISSING");
        for(String section:SECTIONS)if(!Objects.equals(m.get(section),packages.path("").get(section)))throw new IllegalArgumentException("MANIFEST_LOCK_MISMATCH");
        for(var it=packages.fields();it.hasNext();){var entry=it.next();String p=entry.getKey();var node=entry.getValue();
            if(!p.isEmpty()&&!p.matches("node_modules/(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+(?:/node_modules/(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+)*")||p.contains("..")||node.path("link").asBoolean()||node.has("resolved")&&!publicUrl(node.path("resolved").asText()))throw new IllegalArgumentException("PUBLIC_REGISTRY_TREE_ONLY");
            if(!p.isEmpty()&&node.has("name")&&!node.path("name").asText().equals(p.substring(p.lastIndexOf("node_modules/")+13)))throw new IllegalArgumentException("PACKAGE_ALIAS_REQUIRES_MANUAL_REVIEW");
            if(!p.isEmpty()&&(!node.path("version").asText().matches("[0-9]+\\.[0-9]+\\.[0-9]+(?:-[A-Za-z0-9.-]+)?")||!node.path("integrity").asText().startsWith("sha512-")))throw new IllegalArgumentException("LOCK_INTEGRITY_REQUIRED");
            for(String s:SECTIONS)for(var fields=node.path(s).fields();fields.hasNext();){var e=fields.next();if(!e.getKey().matches("(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+")||e.getKey().contains("..")||!e.getValue().isTextual()||!e.getValue().asText().matches("[A-Za-z0-9.*~^<>=| ,+-]+"))throw new IllegalArgumentException("SEMVER_REGISTRY_ONLY");}
        }
        var files=List.of(file("package.json",manifest),file("package-lock.json",lockfile));var components=new NpmManifestParser(json).parseLock(files.get(1),files);
        if(components.isEmpty()||components.stream().anyMatch(c->c.versionResolution()!=VersionResolution.EXACT))throw new IllegalArgumentException("INCOMPLETE_LOCK_TREE");
        return new Input(m,l,List.copyOf(components));
    }
    static JsonNode parse(ObjectMapper json,byte[] data)throws Exception{if(data.length>SourceArchive.EDIT_BYTES||SourceArchive.text(data)==null)throw new IllegalArgumentException("MANIFEST_SIZE_OR_ENCODING");var n=json.reader().with(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION).with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).readTree(data);if(!n.isObject())throw new IllegalArgumentException("JSON_OBJECT_REQUIRED");return n;}
    static ProjectFile file(String path,byte[] bytes){return new ProjectFile(Path.of(path),path,path.equals("package.json")?ProjectFileType.PACKAGE_JSON:ProjectFileType.LOCK_FILE,new String(bytes,java.nio.charset.StandardCharsets.UTF_8).lines().toList());}
    static Target target(Input input,String name,String version){
        var matches=input.components().stream().filter(c->name.equals(c.packageName())&&version.equals(c.version())).toList();if(matches.isEmpty())throw new IllegalArgumentException("TARGET_LOCK_PATH_MISSING");
        var roots=new LinkedHashSet<String>();var sections=new LinkedHashSet<String>();var chains=new ArrayList<List<DependencyContext.Hop>>();var paths=new LinkedHashSet<String>();
        for(var c:matches){if(c.context()==null||!c.context().pathsComplete()||c.context().paths().isEmpty())throw new IllegalArgumentException("INCOMPLETE_TARGET_PATHS");paths.add(c.context().installedPath());
            for(var p:c.context().paths()){if(!p.declarationConfirmed()||p.peer())throw new IllegalArgumentException("UNCONFIRMED_OR_PEER_TARGET");roots.add(p.declaredPackage());sections.add(p.declarationSection());chains.add(p.chain());}}
        if(roots.size()!=1||sections.size()!=1)throw new IllegalArgumentException("MULTIPLE_ROOTS_REQUIRE_MANUAL_PLAN");String root=roots.iterator().next(),section=sections.iterator().next();if(!Set.of("dependencies","devDependencies").contains(section))throw new IllegalArgumentException("OPTIONAL_ROOT_REQUIRES_REVIEW");
        String rootVersion=input.lock().path("packages").path("node_modules/"+root).path("version").asText();if(!rootVersion.matches("[0-9]+\\.[0-9]+\\.[0-9]+"))throw new IllegalArgumentException("STABLE_ROOT_REQUIRED");String range=input.manifest().path(section).path(root).asText();if(!satisfies(range,rootVersion))throw new IllegalArgumentException("ROOT_RANGE_UNSUPPORTED_OR_LOCK_MISMATCH");return new Target(name,version,root,rootVersion,section,range,List.copyOf(paths),List.copyOf(chains));
    }
    static void validateGraph(Input before,Input after,Target target,String candidate){
        var expected=before.manifest().deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)expected.path(target.section())).put(target.root(),candidate);if(!expected.equals(after.manifest()))throw new IllegalArgumentException("MANIFEST_SCOPE_CHANGED");
        var a=before.lock().deepCopy();var b=after.lock().deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)a).remove("packages");((com.fasterxml.jackson.databind.node.ObjectNode)b).remove("packages");if(!a.equals(b))throw new IllegalArgumentException("LOCK_OUTER_METADATA_CHANGED");
        Set<String> oldAffected=affected(before,target.root()),newAffected=affected(after,target.root());var paths=new HashSet<String>();before.lock().path("packages").fieldNames().forEachRemaining(paths::add);after.lock().path("packages").fieldNames().forEachRemaining(paths::add);
        for(String path:paths)if(!path.isEmpty()&&!Objects.equals(before.lock().path("packages").get(path),after.lock().path("packages").get(path))&&!oldAffected.contains(path)&&!newAffected.contains(path))throw new IllegalArgumentException("UNRELATED_LOCK_PATH_CHANGED");
        if(after.components().stream().anyMatch(c->c.packageName().equals(target.name())&&c.version().equals(target.version())))throw new IllegalArgumentException("TARGET_VERSION_REMAINS");
    }
    static Set<String> affected(Input input,String root){var result=new HashSet<String>();for(var c:input.components())if(c.context()!=null&&c.context().paths().stream().anyMatch(p->p.declaredPackage().equals(root)))result.add(c.context().installedPath());return result;}
    static boolean satisfies(String range,String value){if(range==null||!range.matches("[~^]?[0-9]{1,9}\\.[0-9]{1,9}\\.[0-9]{1,9}")||!value.matches("[0-9]{1,9}\\.[0-9]{1,9}\\.[0-9]{1,9}"))return false;String base=range.replaceFirst("^[~^]","");if(compare(value,base)<0)return false;String[] a=base.split("\\."),b=value.split("\\.");if(range.startsWith("~"))return a[0].equals(b[0])&&a[1].equals(b[1]);if(range.startsWith("^"))return a[0].equals(b[0])&&(!a[0].equals("0")||a[1].equals(b[1])&&(!a[1].equals("0")||a[2].equals(b[2])));return compare(value,base)==0;}
    static boolean publicUrl(String s){try{var u=java.net.URI.create(s);return u.getScheme().equals("https")&&u.getHost().equals("registry.npmjs.org")&&u.getPort()==-1&&u.getUserInfo()==null&&u.getRawQuery()==null&&u.getRawFragment()==null;}catch(Exception e){return false;}}
}
