package com.securedeploy.sca;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.project.model.ProjectStructure;
import com.securedeploy.sca.client.VulnerabilityDataSource;
import com.securedeploy.sca.config.ScaProperties;
import com.securedeploy.sca.model.*;
import com.securedeploy.sca.parser.ScaManifestCollector;
import com.securedeploy.sca.persistence.ScaResultConverter;
import com.securedeploy.sca.service.ScaService;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class PythonScaServiceTest {
    ScaService service(VulnerabilityDataSource source) {
        return new ScaService(new ScaManifestCollector(new ObjectMapper()), source, new ScaProperties(true, 1, 5, 500, 100));
    }
    ProjectStructure project(String name, String content) { return new ProjectStructure(Path.of("."), List.of(ScaParserTest.file(name, content))); }
    @Test void onlyExactDeclarationsReachExistingProviderAndSnapshotsRoundTrip() {
        var source = mock(VulnerabilityDataSource.class);
        when(source.lookup(anyList())).thenAnswer(inv -> {
            List<DependencyComponent> list = inv.getArgument(0);
            assertThat(list).extracting(DependencyComponent::packageName).containsExactly("fixture-pin", "fixture-conditional");
            assertThat(list).allMatch(c -> c.ecosystem() == ScaEcosystem.PYPI);
            return new VulnerabilityDataSource.LookupResult(List.of(), new HashSet<>(list.stream().map(DependencyComponent::identity).toList()), false, List.of());
        });
        var result = service(source).analyze(project("requirements.txt", "fixture-pin==1.0\nfixture-range>=2.0\nfixture-conditional==3.0; sys_platform == 'win32'"));
        assertThat(result.summary().dependenciesAnalyzed()).isEqualTo(2);
        assertThat(result.summary().unresolvedDependencies()).isEqualTo(1);
        assertThat(result.status()).isEqualTo(ScaResult.Status.PARTIAL);
        var converter = new ScaResultConverter();
        assertThat(converter.convertToEntityAttribute(converter.convertToDatabaseColumn(result))).isEqualTo(result);
    }
    @Test void cleanLookupAndFailureCannotHaveTheSameCompletionStatus() {
        var source = mock(VulnerabilityDataSource.class);
        when(source.lookup(anyList())).thenAnswer(inv -> {
            List<DependencyComponent> list = inv.getArgument(0);
            return new VulnerabilityDataSource.LookupResult(List.of(), Set.of(list.get(0).identity()), false, List.of());
        });
        var project = project("requirements.txt", "fixture-pin==1.0");
        assertThat(service(source).analyze(project).status()).isEqualTo(ScaResult.Status.COMPLETE);
        doThrow(new IllegalStateException("synthetic upstream private body")).when(source).lookup(anyList());
        var failed = service(source).analyze(project);
        assertThat(failed.status()).isEqualTo(ScaResult.Status.UNAVAILABLE);
        assertThat(failed.summary().dependenciesAnalyzed()).isZero();
        assertThat(failed.warnings().toString()).doesNotContain("synthetic upstream");
    }
    @Test void unsupportedLockAndUnresolvedCannotBecomeZeroVulnerabilitiesSuccess() {
        var source = mock(VulnerabilityDataSource.class);
        for (var input : List.of(project("uv.lock", "version=1"), project("requirements.txt", "fixture>=1.0"),
                project("pyproject.toml", "[project\ndependencies=["))) {
            var result = service(source).analyze(input);
            assertThat(result.status()).isEqualTo(ScaResult.Status.PARTIAL);
            assertThat(result.warnings()).isNotEmpty();
        }
        verifyNoInteractions(source);
    }
}
