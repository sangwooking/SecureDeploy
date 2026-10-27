package com.securedeploy.sca.client;

import com.securedeploy.sca.model.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class OsvAlias29BoundaryTest {
    DependencyVulnerability row(ScaEcosystem ecosystem,String name,String id,List<String> aliases,String path) {
        return new DependencyVulnerability(ecosystem,name,"1.0.0",id,aliases,"Offline fixture",null,null,List.of(),List.of("1.0.1"),null,null,List.of(),List.of(path),List.of());
    }
    @Test void aliasIdentityNeverMergesDistinctPackagesOrEcosystems() {
        var warnings=new ArrayList<String>();
        var a=row(ScaEcosystem.NPM,"first","GHSA-offline-a",List.of("CVE-2099-0029"),"package-lock.json");
        var b=row(ScaEcosystem.NPM,"second","GHSA-offline-b",List.of("CVE-2099-0029"),"package-lock.json");
        var c=row(ScaEcosystem.PYPI,"first","PYSEC-offline-c",List.of("CVE-2099-0029"),"requirements.txt");
        assertThat(OsvAliasDeduplicator.merge(List.of(a,b,c),warnings)).hasSize(3);assertThat(warnings).isEmpty();
    }
    @Test void sharedAliasPreservesEveryPathButAbsentIdentityEvidenceCannotEraseAnAdvisory() {
        var warnings=new ArrayList<String>();
        var a=row(ScaEcosystem.NPM,"first","GHSA-offline-a",List.of("CVE-2099-0029"),"package-lock.json");
        var b=row(ScaEcosystem.NPM,"first","TEST-offline-b",List.of("CVE-2099-0029"),"sub/package-lock.json");
        var c=row(ScaEcosystem.NPM,"first","TEST-offline-unrelated",List.of(),"other/package-lock.json");
        var result=OsvAliasDeduplicator.merge(List.of(c,b,a),warnings);assertThat(result).hasSize(2);
        assertThat(result.stream().filter(f->f.osvId().equals(a.osvId())).findFirst().orElseThrow().sourceFiles()).containsExactly("package-lock.json","sub/package-lock.json");
        assertThat(result).anyMatch(f->f.osvId().equals(c.osvId()));assertThat(warnings).isEmpty();
    }
}
