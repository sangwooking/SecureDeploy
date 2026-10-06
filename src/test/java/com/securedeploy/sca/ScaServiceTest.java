package com.securedeploy.sca;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.project.model.ProjectStructure;
import com.securedeploy.sca.client.VulnerabilityDataSource;
import com.securedeploy.sca.config.ScaProperties;
import com.securedeploy.sca.model.*;
import com.securedeploy.sca.parser.ScaManifestCollector;
import com.securedeploy.sca.service.ScaService;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class ScaServiceTest {
    private ScaService service(VulnerabilityDataSource provider) {
        return new ScaService(new ScaManifestCollector(new ObjectMapper()), provider, new ScaProperties(true, 1, 5, 500, 100));
    }
    @Test void unresolvedVersionsNeverReachProvider() {
        var provider = mock(VulnerabilityDataSource.class);
        var project = new ProjectStructure(Path.of("."), List.of(ScaParserTest.file("package.json", "{\"dependencies\":{\"lodash\":\"^4.17.0\"}}")));
        var result = service(provider).analyze(project);
        assertThat(result.status()).isEqualTo(ScaResult.Status.PARTIAL);
        assertThat(result.summary().dependenciesAnalyzed()).isZero();
        assertThat(result.summary().unresolvedDependencies()).isEqualTo(1);
        verifyNoInteractions(provider);
    }
    @Test void providerFailureIsContainedAndInventoryRemainsAvailable() {
        var provider = mock(VulnerabilityDataSource.class);
        when(provider.lookup(anyList())).thenThrow(new IllegalStateException("not shown to users"));
        var project = new ProjectStructure(Path.of("."), List.of(ScaParserTest.file("package.json", "{\"dependencies\":{\"lodash\":\"4.17.10\"}}")));
        var result = service(provider).analyze(project);
        assertThat(result.status()).isEqualTo(ScaResult.Status.UNAVAILABLE);
        assertThat(result.components()).hasSize(1);
        assertThat(result.warnings().toString()).doesNotContain("not shown to users");
    }
}
