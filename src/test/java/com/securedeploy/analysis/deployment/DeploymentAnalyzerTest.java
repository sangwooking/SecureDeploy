package com.securedeploy.analysis.deployment;

import com.securedeploy.project.model.*;
import com.securedeploy.project.service.ProjectFileCollector;
import com.securedeploy.analysis.python.*;
import com.securedeploy.analysis.typescript.*;
import com.securedeploy.rule.rules.*;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class DeploymentAnalyzerTest {
    static ProjectFile file(String path, String content) {
        return new ProjectFile(Path.of("/unopened-source").resolve(path), path,
                new ProjectFileCollector().resolveAnalysisFileType(Path.of(path)).orElseThrow(), content.lines().toList());
    }
    static DeploymentSnapshot inspect(ProjectFile... files) {
        return DeploymentAnalyzer.analyze(new ProjectStructure(Path.of("/unopened-source"), List.of(files)), null);
    }
    static final String RISKY = """
            services:
              executor:
                privileged: true
                network_mode: host
                user: '0:1000'
                cap_add: [SYS_ADMIN]
                volumes: ['/var/run/docker.sock:/var/run/docker.sock:ro', '/etc:/host/etc:ro']
                ports: ['8080:80']
                security_opt: ['seccomp:unconfined']
            """;
    @Test void serviceStructureAndAllComposeNamesShareEvidenceWithoutDuplicatingLegacyRules() {
        for (String name : List.of("compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml")) {
            var input = file(name, RISKY); var result = inspect(input);
            assertThat(new DockerComposeSecurityRule().evaluate(input)).extracting(m -> m.ruleId())
                    .containsExactly("DOCKER_PRIVILEGED", "DOCKER_HOST_NETWORK");
            assertThat(result.findings()).extracting(DeploymentSnapshot.Finding::ruleId).containsExactly(
                    "COMPOSE_ROOT_OVERRIDE", "COMPOSE_CAPABILITY", "COMPOSE_SECURITY_DISABLED", "COMPOSE_SOCKET", "COMPOSE_HOST_MOUNT", "COMPOSE_PORT_BINDING");
            assertThat(result.findings()).allMatch(f -> f.priority().equals("REVIEW_REQUIRED") && f.comparisonPolicy().equals("NOT_COMPARED"));
        }
    }
    @Test void commentsAndNonServiceDataAreNotRuntimeOptions() {
        var input = file("compose.yml", """
                x-note: 'privileged: true network_mode: host'
                services:
                  frontend:
                    # privileged: true
                    environment: {privileged: 'true', network_mode: host}
                    privileged: false
                    user: '1000'
                    ports: ['127.0.0.1:8080:80', '[::1]:8081:80']
                    volumes: [cache:/cache]
                    security_opt: [no-new-privileges:true]
                """);
        assertThat(new DockerComposeSecurityRule().evaluate(input)).isEmpty();
        assertThat(inspect(input).findings()).isEmpty();
    }
    @Test void redactedNamesCannotMergeUnrelatedServicesOnTheSameLine() throws Exception {
        var input = file("compose.yml", "services: {'first@example.invalid': {user: '0'}, 'second@example.invalid': {user: '0'}}");
        var result = inspect(input);
        assertThat(result.findings()).hasSize(2);
        assertThat(result.findings()).extracting(DeploymentSnapshot.Finding::findingId).doesNotHaveDuplicates();
        assertThat(new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(result)).doesNotContain("first@example", "second@example");
    }
    @Test void longSyntaxServicesRemainSeparateAndExternalReferencesAreNotLoaded() {
        var result = inspect(file("compose.yaml", """
                include: /outside/unreadable.yml
                services:
                  first:
                    user: '0'
                    volumes: [{type: bind, source: /run/docker.sock, target: /run/docker.sock, read_only: true}]
                    ports: [{target: 80, published: '8080', host_ip: '0.0.0.0'}]
                  second:
                    user: '1000'
                    ports: [{target: 80, published: '8081', host_ip: '127.0.0.1'}]
                  third:
                    user: '${APP_USER}'
                    privileged: '${PRIVILEGED:-false}'
                    ports: ['${BIND}:8082:80']
                    extends: {file: /outside/never-read.yml, service: original}
                """));
        assertThat(result.findings()).hasSize(3).allMatch(f -> f.scope().equals("service:first"));
        assertThat(result.files().get(0).observations()).filteredOn(o -> o.scope().equals("service:third"))
                .allMatch(o -> o.valueStatus().equals("UNKNOWN"));
        assertThat(result.files().get(0).limitations()).contains("EXTERNAL_INCLUDE_NOT_RESOLVED", "SERVICE_ACTIVATION_OR_REFERENCE_UNRESOLVED");
    }
    @Test void duplicateTagsAliasesInvalidAndOversizeInputsCannotBecomeSafe() {
        for (String source : List.of("services: [", "services: {a: {user: root, user: '1000'}}",
                "services: !!java.lang.ProcessBuilder {}", "services: &loop {a: *loop}",
                "x: &defaults {user: root}\nservices: {a: {<<: *defaults}}")) {
            var result = inspect(file("compose.yml", source));
            assertThat(result.files().get(0).status()).isEqualTo("PARSE_FAILED");
            assertThat(result.findings()).isEmpty(); assertThat(result.status()).isEqualTo("PARTIAL");
        }
        assertThat(inspect(file("compose.yml", "x".repeat(100_001))).files().get(0).status()).isEqualTo("LIMIT_EXCEEDED");
    }
    @Test void dockerFinalStageAndComposeOverrideAreNotMergedIntoAnInventedRuntime() {
        var docker = file("Dockerfile", "FROM alpine AS builder\nUSER root\nFROM builder AS runtime\nUSER 1000\n");
        assertThat(new DockerRootUserRule().evaluate(docker)).isEmpty();
        var result = inspect(docker, file("compose.yml", "services: {web: {build: {context: '.', target: builder}, user: '0'}}"));
        assertThat(result.findings()).hasSize(1);
        assertThat(result.files().get(0).limitations()).contains("DOCKERFILE_TARGET_IMAGE_AND_COMPOSE_USER_NOT_MERGED");
        assertThat(new DockerRootUserRule().evaluate(file("Dockerfile", "FROM alpine\nUSER root\n"))).hasSize(1);
        assertThat(new DockerRootUserRule().evaluate(file("Dockerfile", "FROM alpine\n"))).isEmpty();
    }
    @Test void wranglerInventoryRedactsValuesAndDoesNotInventSecretsOrEnvironmentInheritance() throws Exception {
        var secret = "synthetic-private-value-not-a-real-key";
        for (var input : List.of(file("wrangler.jsonc", "{ // comment\n\"vars\":{\"API_KEY\":\"" + secret + "\"},\"routes\":[\"example.invalid/*\"],\"env\":{\"production\":{\"workers_dev\":false,\"d1_databases\":[]}},}"),
                file("wrangler.toml", "[vars]\nAPI_KEY='" + secret + "'\n[env.production]\nworkers_dev=false\nd1_databases=[]"))) {
            var result = inspect(input);
            assertThat(result.files().get(0).status()).isEqualTo("PARSED"); assertThat(result.findings()).isEmpty();
            assertThat(result.files().get(0).observations()).anyMatch(o -> o.scope().equals("env:production"));
            assertThat(new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(result)).doesNotContain(secret, "example.invalid/*");
        }
        assertThat(inspect(file("wrangler.json", "{\"vars\":{},\"vars\":{}}" )).files().get(0).status()).isEqualTo("PARSE_FAILED");
        assertThat(inspect(file("wrangler.json", "{} {}" )).files().get(0).status()).isEqualTo("PARSE_FAILED");
        assertThat(inspect(file("wrangler.toml", "[vars\n" )).files().get(0).status()).isEqualTo("PARSE_FAILED");
        var unknown = inspect(file("wrangler.json", "{\"secrets\":{\"required\":[\"API_KEY\"]}}"));
        assertThat(unknown.files().get(0).observations().get(0).valueStatus()).isEqualTo("UNKNOWN");
    }
    @Test void djangoUsesTrustedAstAndPreservesOldSnapshotCompatibility() {
        var source = file("settings.py", "ROOT_URLCONF='app.urls'\nINSTALLED_APPS=[]\nDEBUG=True\nSECRET_KEY='synthetic-only'\nALLOWED_HOSTS=['*']\nSESSION_COOKIE_SECURE=False\n");
        var project = new ProjectStructure(Path.of("/unopened-source"), List.of(source));
        var python = new PythonServerAnalyzer(new PythonAnalysisProperties()).analyze(project);
        assertThat(python.deploymentAnalysis()).isNotNull();
        var result = DeploymentAnalyzer.analyze(project, python.deploymentAnalysis());
        assertThat(result.findings()).hasSize(4);
        var root = ServerAnalysisSnapshot.unavailable("NOT_APPLICABLE", List.of(), "NO_TS").withPythonAnalysis(python).withDeploymentAnalysis(result);
        var converter = new ServerAnalysisConverter(); String json = converter.convertToDatabaseColumn(root);
        assertThat(json).doesNotContain("synthetic-only", "/unopened-source");
        assertThat(converter.convertToEntityAttribute(json)).isEqualTo(root);
        assertThat(converter.convertToEntityAttribute("{\"schemaVersion\":1,\"analyzerVersion\":\"ts-server-v1\",\"files\":[],\"findings\":[],\"sqlUses\":[],\"authorizationContexts\":[],\"limitations\":[]}").deploymentAnalysis()).isNull();
    }
}
