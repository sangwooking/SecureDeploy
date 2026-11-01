package com.securedeploy.editing;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import java.util.*;
class NpmIsolationPolicyTest {
    NpmIsolationRunner disabled(){return new NpmIsolationRunner(new ObjectMapper(),mock(NpmRegistry.class),new MockEnvironment());}
    @Test void defaultDisabledAndMissingImageCannotSpawnHostFallback() {
        var runner=disabled();try{assertFalse(runner.available());assertThrows(IllegalStateException.class,()->runner.generate(new byte[0],new byte[0]));}finally{runner.close();}
        var missing=new NpmIsolationRunner(new ObjectMapper(),mock(NpmRegistry.class),new MockEnvironment().withProperty("securedeploy.editing.npm-isolation.enabled","true"));assertFalse(missing.available());missing.close();
    }
    @Test void commandsNeverMountHostOrEnableNetworkOrPrivileges() {
        var runner=disabled();try{var args=runner.containerArgs("securedeploy-npm-"+UUID.randomUUID(),"TRUSTED_SCRIPT");
            for(String flag:List.of("--network=none","--read-only","--cap-drop=ALL","--security-opt=no-new-privileges","--user=65532:65532","--memory=512m","--memory-swap=512m","--cpus=1","--pids-limit=32","--pull=never"))assertTrue(args.contains(flag));
            assertTrue(args.stream().noneMatch(a->a.equals("-v")||a.startsWith("--mount")||a.equals("--privileged")||a.startsWith("--env")||a.contains("docker.sock")));
            assertEquals(3,args.stream().filter(a->a.startsWith("--tmpfs=")&&a.contains("noexec,nosuid,nodev,size=")).count());
        }finally{runner.close();}
    }
    @Test void canonicalReferenceKeepsExactOfficialDigest(){String input="node@sha256:"+"a".repeat(64);assertEquals("docker.io/library/"+input,NpmIsolationRunner.canonicalImage(input));assertFalse(NpmIsolationRunner.validImage("other/node@sha256:"+"a".repeat(64)));}
    @Test void metadataBudgetBoundsUtf8AndEscapesBeforeAccumulatingBodies()throws Exception {
        var json=new ObjectMapper();for(String text:List.of("ascii","홍익🙂","\"\\\n",String.valueOf((char)0)))assertTrue(NpmIsolationRunner.jsonStringBudget(text)>=json.writeValueAsBytes(text).length);
    }
    @Test void brokerNamesAndImageAreNotArbitraryUrlsOrCommandArguments(){
        for(String value:List.of("file:../x","../../x","git+https://example.invalid/x","https://127.0.0.1/x","a%2fb","--registry=x","a b","a;owned"))assertThrows(IllegalArgumentException.class,()->NpmIsolationRunner.packageFromMiss(value));
        assertEquals("@scope/name",NpmIsolationRunner.packageFromMiss("@scope/name"));assertTrue(NpmIsolationRunner.validImage("node@sha256:"+"a".repeat(64)));assertFalse(NpmIsolationRunner.validImage("node:latest"));assertFalse(NpmIsolationRunner.validImage("private/image@sha256:"+"a".repeat(64)));
    }
}
