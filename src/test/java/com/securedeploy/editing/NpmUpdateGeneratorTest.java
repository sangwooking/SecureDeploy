package com.securedeploy.editing;
import com.fasterxml.jackson.databind.*;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class NpmUpdateGeneratorTest {
 final ObjectMapper json=new ObjectMapper();final NpmUpdateGenerator generator=new NpmUpdateGenerator(json,false,"/not-executed");
 byte[] bytes(String s){return s.getBytes(StandardCharsets.UTF_8);}
 String manifest="{\"name\":\"fixture\",\"devDependencies\":{\"parent\":\"1.0.0\"},\"scripts\":{\"install\":\"do-not-execute\"}}";
 String lock="{\"lockfileVersion\":3,\"packages\":{\"\":{\"name\":\"fixture\",\"devDependencies\":{\"parent\":\"1.0.0\"}},\"node_modules/leaf\":{\"version\":\"1.0.0\",\"resolved\":\"https://registry.npmjs.org/leaf/-/leaf-1.0.0.tgz\",\"integrity\":\"sha512-old\",\"dev\":true}}}";
 @Test void disabledGeneratorNeverStartsAnExecutable(){assertThrows(Exception.class,()->generator.generate(bytes(manifest),bytes(lock),"leaf","1.0.0","1.0.1",false));}
 @Test void onlyRegistryLeafAndConsistentRootContractsAreAccepted()throws Exception{
  generator.validateInput(json.readTree(manifest),json.readTree(lock),"leaf","1.0.0","1.0.1");
  for(String invalid:new String[]{lock.replace("https://registry.npmjs.org/","https://private.invalid/"),lock.replace("\"lockfileVersion\":3","\"lockfileVersion\":2"),lock.replace("\"1.0.0\"}},","\"2.0.0\"}},")})assertThrows(Exception.class,()->generator.validateInput(json.readTree(manifest),json.readTree(invalid),"leaf","1.0.0","1.0.1"));
 }
 @Test void modelCannotRewriteScriptsOrOtherPackagesAndIntegrityMustMatch()throws Exception{
  var after=(com.fasterxml.jackson.databind.node.ObjectNode)json.readTree(manifest);after.putObject("overrides").put("leaf@1.0.0","1.0.1");String updated=lock.replace("leaf-1.0.0.tgz","leaf-1.0.1.tgz").replace("\"version\":\"1.0.0\"","\"version\":\"1.0.1\"").replace("sha512-old","sha512-new");
  var result=generator.validateOutput(bytes(manifest),bytes(lock),json.writeValueAsBytes(after),bytes(updated),"leaf","1.0.0","1.0.1",false,"sha512-new","https://registry.npmjs.org/leaf/-/leaf-1.0.1.tgz");assertEquals(1,result.changedPackages().size());
  assertThrows(Exception.class,()->generator.validateOutput(bytes(manifest),bytes(lock),json.writeValueAsBytes(after),bytes(updated),"leaf","1.0.0","1.0.1",false,"sha512-wrong","https://registry.npmjs.org/leaf/-/leaf-1.0.1.tgz"));
  var missing=(com.fasterxml.jackson.databind.node.ObjectNode)json.readTree(updated);((com.fasterxml.jackson.databind.node.ObjectNode)missing.path("packages")).remove("node_modules/leaf");
  assertThrows(Exception.class,()->generator.validateOutput(bytes(manifest),bytes(lock),json.writeValueAsBytes(after),json.writeValueAsBytes(missing),"leaf","1.0.0","1.0.1",false,"sha512-new","https://registry.npmjs.org/leaf/-/leaf-1.0.1.tgz"));
  ((com.fasterxml.jackson.databind.node.ObjectNode)after.path("scripts")).put("install","changed");assertThrows(Exception.class,()->generator.validateOutput(bytes(manifest),bytes(lock),json.writeValueAsBytes(after),bytes(updated),"leaf","1.0.0","1.0.1",false,"sha512-new","https://registry.npmjs.org/leaf/-/leaf-1.0.1.tgz"));
 }
 @Test void directUpdatePreservesScriptsAndRejectsNonRegistryNestedSpecifications()throws Exception{
  String m="{\"dependencies\":{\"leaf\":\"^1.0.0\"},\"scripts\":{\"install\":\"do-not-execute\"}}";
  String l=lock.replace("\"name\":\"fixture\",\"devDependencies\":{\"parent\":\"1.0.0\"}","\"dependencies\":{\"leaf\":\"^1.0.0\"}");
  String nextM=m.replace("^1.0.0","1.0.1"),nextL=l.replace("^1.0.0","1.0.1").replace("leaf-1.0.0.tgz","leaf-1.0.1.tgz").replace("\"version\":\"1.0.0\"","\"version\":\"1.0.1\"").replace("sha512-old","sha512-new");
  assertEquals(1,generator.validateOutput(bytes(m),bytes(l),bytes(nextM),bytes(nextL),"leaf","1.0.0","1.0.1",true,"sha512-new","https://registry.npmjs.org/leaf/-/leaf-1.0.1.tgz").changedPackages().size());
  var nested=(com.fasterxml.jackson.databind.node.ObjectNode)json.readTree(l);((com.fasterxml.jackson.databind.node.ObjectNode)nested.path("packages").path("node_modules/leaf")).putObject("peerDependencies").put("remote","https://private.invalid/package.tgz");
  assertThrows(Exception.class,()->generator.validateInput(json.readTree(m),nested,"leaf","1.0.0","1.0.1"));
  ((com.fasterxml.jackson.databind.node.ObjectNode)nested.path("packages").path("node_modules/leaf").path("peerDependencies")).put("remote","^1.0.0-beta.2");generator.validateInput(json.readTree(m),nested,"leaf","1.0.0","1.0.1");
 }


 @Test void unchangedNestedTargetWithoutResolvedUrlRejectsFalseDirectSuccess()throws Exception{
  String m="{\"dependencies\":{\"leaf\":\"1.0.0\"}}";
  var l=(com.fasterxml.jackson.databind.node.ObjectNode)json.readTree(lock);((com.fasterxml.jackson.databind.node.ObjectNode)l.path("packages")).set("",json.readTree(m));
  ((com.fasterxml.jackson.databind.node.ObjectNode)l.path("packages")).putObject("node_modules/parent/node_modules/leaf").put("version","1.0.0");
  var next=l.deepCopy();var leaf=(com.fasterxml.jackson.databind.node.ObjectNode)next.path("packages").path("node_modules/leaf");leaf.put("version","1.0.1").put("resolved","https://registry.npmjs.org/leaf/-/leaf-1.0.1.tgz").put("integrity","sha512-new");
  ((com.fasterxml.jackson.databind.node.ObjectNode)next.path("packages").path("").path("dependencies")).put("leaf","1.0.1");
  var e=assertThrows(IllegalArgumentException.class,()->generator.validateOutput(bytes(m),json.writeValueAsBytes(l),bytes(m.replace("1.0.0","1.0.1")),json.writeValueAsBytes(next),"leaf","1.0.0","1.0.1",true,"sha512-new","https://registry.npmjs.org/leaf/-/leaf-1.0.1.tgz"));assertEquals("TARGET_VERSION_REMAINS",e.getMessage());
 }
}
