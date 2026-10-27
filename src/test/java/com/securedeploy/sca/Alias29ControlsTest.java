package com.securedeploy.sca;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.sca.client.*;
import com.securedeploy.sca.config.ScaProperties;
import com.securedeploy.sca.model.*;
import com.securedeploy.sca.parser.VersionClassifier;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

/** Frozen offline OSV responses. Not a live database accuracy measurement. */
class Alias29ControlsTest {
    static String advisory(String id,String alias,String fixed) {
        return "{\"id\":\""+id+"\",\"aliases\":[\""+alias+"\"],\"affected\":[{\"package\":{\"ecosystem\":\"npm\",\"name\":\"example-a\"},\"ranges\":[{\"type\":\"SEMVER\",\"events\":[{\"introduced\":\"0\"},{\"fixed\":\""+fixed+"\"}]}]}]}";
    }
    VulnerabilityDataSource.LookupResult lookup(List<DependencyComponent> components,boolean conflict) {
        var builder=RestClient.builder().baseUrl("https://api.osv.dev");var server=MockRestServiceServer.bindTo(builder).build();
        var client=new OsvClient(builder.build(),new ObjectMapper(),new ScaProperties(true,1,10,500,100));
        String hit="{\"vulns\":[{\"id\":\"CVE-2099-0029\"},{\"id\":\"GHSA-offline-29\"}]}";
        int identities=(int)components.stream().map(DependencyComponent::identity).distinct().count();
        server.expect(requestTo("https://api.osv.dev/v1/querybatch")).andRespond(withSuccess("{\"results\":["+String.join(",",Collections.nCopies(identities,hit))+"]}",MediaType.APPLICATION_JSON));
        server.expect(requestTo("https://api.osv.dev/v1/vulns/CVE-2099-0029")).andRespond(withSuccess(advisory("CVE-2099-0029","GHSA-offline-29","1.0.1"),MediaType.APPLICATION_JSON));
        server.expect(requestTo("https://api.osv.dev/v1/vulns/GHSA-offline-29")).andRespond(withSuccess(advisory("GHSA-offline-29","CVE-2099-0029",conflict?"2.0.0":"1.0.1"),MediaType.APPLICATION_JSON));
        var result=client.lookup(components);server.verify();return result;
    }
    DependencyComponent dep(String version,String file){return VersionClassifier.component(ScaEcosystem.NPM,"example-a",version,"dependencies",true,file,1);}
    @Test void aliasesDoNotDoubleCountOneVersionOrEraseSourcePaths() {
        var r=lookup(List.of(dep("1.0.0","package-lock.json"),dep("1.0.0","sub/package-lock.json")),false);
        boolean before="before".equals(System.getenv("SECUREDEPLOY_SUPPLY29_STAGE"));
        assertThat(r.findings()).hasSize(before?2:1);
        assertThat(r.findings()).allSatisfy(f->assertThat(f.sourceFiles()).containsExactly("package-lock.json","sub/package-lock.json"));
        if(!before){assertThat(r.findings().get(0).osvId()).isEqualTo("GHSA-offline-29");assertThat(r.findings().get(0).aliases()).contains("CVE-2099-0029");}
    }
    @Test void distinctInstalledVersionsRemainDistinctImpacts() {
        var r=lookup(List.of(dep("1.0.0","package-lock.json"),dep("0.9.0","sub/package-lock.json")),false);
        boolean before="before".equals(System.getenv("SECUREDEPLOY_SUPPLY29_STAGE"));assertThat(r.findings()).hasSize(before?4:2);
        assertThat(r.findings()).extracting(DependencyVulnerability::installedVersion).contains("1.0.0","0.9.0");
    }
    @Test void conflictingFixMetadataIsPreservedInsteadOfClaimingASafeUpgrade() {
        var r=lookup(List.of(dep("1.0.0","package-lock.json")),true);assertThat(r.findings()).hasSize(2);
        if(!"before".equals(System.getenv("SECUREDEPLOY_SUPPLY29_STAGE"))){assertThat(r.incomplete()).isTrue();assertThat(r.warnings()).isNotEmpty();}
    }
}
