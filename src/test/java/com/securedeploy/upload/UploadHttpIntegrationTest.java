package com.securedeploy.upload;

import com.fasterxml.jackson.databind.*;
import com.securedeploy.global.util.FileUtils;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import static org.assertj.core.api.Assertions.*;

// Embedded HTTP server exercises servlet multipart limits, which MockMvc does not enforce.
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.servlet.multipart.max-file-size=1KB", "spring.servlet.multipart.max-request-size=2KB",
        "securedeploy.storage.max-expanded-size=2KB", "securedeploy.storage.max-archive-entries=5",
        "securedeploy.ai.provider=template", "securedeploy.sca.enabled=false"})
class UploadHttpIntegrationTest {
    static final Path WORK = Path.of(System.getProperty("java.io.tmpdir"), "zip-http-" + UUID.randomUUID());
    @DynamicPropertySource static void properties(DynamicPropertyRegistry registry) {
        registry.add("securedeploy.storage.temp-dir", WORK::toString);
    }
    @LocalServerPort int port;
    @Autowired ObjectMapper mapper;
    final HttpClient client = HttpClient.newHttpClient();
    String token;

    @BeforeEach void signup() throws Exception {
        var data = Map.of("email", UUID.randomUUID() + "@upload-test.invalid", "name", "Upload fixture",
                "password", "Fake-upload-fixture-only-1234");
        var response = client.send(HttpRequest.newBuilder(uri("/api/auth/signup")).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(mapper.writeValueAsBytes(data))).build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);
        token = mapper.readTree(response.body()).path("accessToken").asText();
    }
    @AfterAll static void cleanup() { FileUtils.deleteRecursively(WORK); }
    URI uri(String path) { return URI.create("http://localhost:" + port + path); }

    HttpResponse<String> sendZip(String endpoint, byte[] zip, int extraFieldLength) throws Exception {
        var body = new ByteArrayOutputStream();
        body.write(("--fixture\r\nContent-Disposition: form-data; name=\"file\"; filename=\"fixture.zip\"\r\nContent-Type: application/zip\r\n\r\n").getBytes(StandardCharsets.UTF_8));
        body.write(zip);
        if (extraFieldLength > 0) body.write(("\r\n--fixture\r\nContent-Disposition: form-data; name=\"extra\"\r\n\r\n" + "x".repeat(extraFieldLength)).getBytes(StandardCharsets.UTF_8));
        body.write("\r\n--fixture--\r\n".getBytes(StandardCharsets.UTF_8));
        return client.send(HttpRequest.newBuilder(uri(endpoint)).header("Authorization", "Bearer " + token)
                .header("Content-Type", "multipart/form-data; boundary=fixture")
                .POST(HttpRequest.BodyPublishers.ofByteArray(body.toByteArray())).build(), HttpResponse.BodyHandlers.ofString());
    }
    byte[] archive(Map<String, String> entries) throws Exception {
        var bytes = new ByteArrayOutputStream();
        try (var zip = new ZipOutputStream(bytes)) {
            for (var entry : entries.entrySet()) {
                zip.putNextEntry(new ZipEntry(entry.getKey()));
                zip.write(entry.getValue().getBytes(StandardCharsets.UTF_8));
                zip.closeEntry();
            }
        }
        return bytes.toByteArray();
    }
    void assertClean() throws Exception {
        if (Files.exists(WORK)) try (var paths = Files.list(WORK)) { assertThat(paths.toList()).isEmpty(); }
    }

    @Test void normalZipThenRescanHasMetadataAndCleansBothWorkspaces() throws Exception {
        var policyResponse = client.send(HttpRequest.newBuilder(uri("/api/reviews/upload-policy"))
                .header("Authorization", "Bearer " + token).build(), HttpResponse.BodyHandlers.ofString());
        assertThat(policyResponse.statusCode()).isEqualTo(200);
        assertThat(mapper.readTree(policyResponse.body()).path("maxZipBytes").asLong()).isEqualTo(1024);
        var first = sendZip("/api/reviews/upload", archive(Map.of("application.properties", "debug=true\n")), 0);
        assertThat(first.statusCode()).isEqualTo(200);
        JsonNode before = mapper.readTree(first.body());
        var second = sendZip("/api/projects/" + before.path("projectId").asLong() + "/reviews/upload",
                archive(Map.of("application.properties", "debug=false\n")), 0);
        assertThat(second.statusCode()).isEqualTo(200);
        JsonNode after = mapper.readTree(second.body());
        assertThat(after.path("projectId")).isEqualTo(before.path("projectId"));
        assertThat(after.at("/comparison/counts/RESOLVED").asInt()).isEqualTo(1);
        assertClean();
    }

    @Test void realMultipartFileAndRequestOverheadLimitsReturn413Not500() throws Exception {
        var fileExceeded = sendZip("/api/reviews/upload", new byte[1025], 0);
        assertThat(fileExceeded.statusCode()).isEqualTo(413);
        assertThat(mapper.readTree(fileExceeded.body()).path("message").asText()).contains("최대 1024B", "node_modules");
        var requestExceeded = sendZip("/api/reviews/upload", new byte[10], 2200);
        assertThat(requestExceeded.statusCode()).isEqualTo(413);
        assertClean();
    }

    @Test void invalidArchiveExpandedLimitAndEntryLimitAreFriendly4xxAndNeverSaveReview() throws Exception {
        var expanded = sendZip("/api/reviews/upload", archive(Map.of("node_modules/huge.txt", "a".repeat(8000))), 0);
        assertThat(expanded.statusCode()).isEqualTo(413);
        assertThat(mapper.readTree(expanded.body()).path("message").asText()).contains("압축을 해제한 프로젝트");
        var entries = new LinkedHashMap<String, String>();
        for (int i = 0; i < 6; i++) entries.put("dir" + i + "/", "");
        assertThat(sendZip("/api/reviews/upload", archive(entries), 0).statusCode()).isEqualTo(413);
        assertThat(sendZip("/api/reviews/upload", "not-zip".getBytes(), 0).statusCode()).isEqualTo(400);
        assertThat(sendZip("/api/reviews/upload", archive(Map.of("../escape", "fake")), 0).statusCode()).isEqualTo(400);
        assertClean();
        var history = client.send(HttpRequest.newBuilder(uri("/api/reviews")).header("Authorization", "Bearer " + token).build(), HttpResponse.BodyHandlers.ofString());
        assertThat(mapper.readTree(history.body()).size()).isZero();
    }
}
