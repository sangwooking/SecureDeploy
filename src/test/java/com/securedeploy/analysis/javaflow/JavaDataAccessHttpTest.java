package com.securedeploy.analysis.javaflow;

import com.fasterxml.jackson.databind.*;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import static org.assertj.core.api.Assertions.*;

/** Real loopback HTTP, isolated H2, synthetic source only. No external calls. */
@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT,properties={
        "server.address=127.0.0.1","spring.datasource.url=jdbc:h2:mem:java-http;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
        "securedeploy.ai.provider=template","securedeploy.sca.enabled=false","securedeploy.threat-intelligence.enabled=false"})
class JavaDataAccessHttpTest {
    @LocalServerPort int port;
    @Autowired ObjectMapper json;
    final HttpClient http=HttpClient.newHttpClient();
    URI uri(String path){return URI.create("http://127.0.0.1:"+port+path);}
    @Test void actualHttpUploadAndDetailUsePackagedV3WorkerWithoutUserDatabase() throws Exception {
        var signup=HttpRequest.newBuilder(uri("/api/auth/signup")).header("Content-Type","application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(Map.of("email",UUID.randomUUID()+"@java-http.invalid","password",UUID.randomUUID().toString(),"name","Synthetic fixture")))).build();
        var signed=http.send(signup,HttpResponse.BodyHandlers.ofByteArray());assertThat(signed.statusCode()).isEqualTo(200);
        String token=json.readTree(signed.body()).path("accessToken").asText();assertThat(token).isNotBlank();
        var sources=Map.of("Endpoint.java","package sample; import org.springframework.web.bind.annotation.*; @RestController class Endpoint {@org.springframework.beans.factory.annotation.Autowired Mapper mapper; @GetMapping(\"/\") void lookup(@RequestParam String value){mapper.lookup(value);}}",
                "Mapper.java","package sample; interface Mapper {String lookup(@org.apache.ibatis.annotations.Param(\"value\") String value);}",
                "queries.xml","<mapper namespace=\"sample.Mapper\"><select id=\"lookup\">SELECT * FROM entries WHERE name=${value}</select></mapper>");
        var archive=new ByteArrayOutputStream();
        try(var zip=new ZipOutputStream(archive)){for(var entry:sources.entrySet()){zip.putNextEntry(new ZipEntry("fixture/"+entry.getKey()));zip.write(entry.getValue().getBytes(StandardCharsets.UTF_8));zip.closeEntry();}}
        String boundary="fixture-"+UUID.randomUUID();var body=new ByteArrayOutputStream();
        body.write(("--"+boundary+"\r\nContent-Disposition: form-data; name=\"file\"; filename=\"fixture.zip\"\r\nContent-Type: application/zip\r\n\r\n").getBytes(StandardCharsets.UTF_8));
        body.write(archive.toByteArray());body.write(("\r\n--"+boundary+"--\r\n").getBytes(StandardCharsets.UTF_8));
        var request=HttpRequest.newBuilder(uri("/api/reviews/upload")).header("Authorization","Bearer "+token)
                .header("Content-Type","multipart/form-data; boundary="+boundary).POST(HttpRequest.BodyPublishers.ofByteArray(body.toByteArray())).build();
        var response=http.send(request,HttpResponse.BodyHandlers.ofByteArray());assertThat(response.statusCode()).isEqualTo(200);
        var result=json.readTree(response.body());
        assertThat(result.at("/serverAnalysis/javaAnalysis/analysis/version").asText()).isEqualTo(JavaSqlWorker.VERSION);
        assertThat(result.at("/serverAnalysis/javaAnalysis/findings")).hasSize(1);
        assertThat(result.at("/serverAnalysis/javaAnalysis/analysis/dataAccess").toString()).contains("INPUT_SUBSTITUTION");
        assertThat(result.path("securityScore").asInt()).isEqualTo(100);
        assertThat(result.at("/riskAssessment/prioritySummary/BLOCKING").asInt()).isZero();
        var detail=http.send(HttpRequest.newBuilder(uri("/api/reviews/"+result.path("reviewId").asLong())).header("Authorization","Bearer "+token).GET().build(),HttpResponse.BodyHandlers.ofByteArray());
        assertThat(detail.statusCode()).isEqualTo(200);assertThat(json.readTree(detail.body()).path("serverAnalysis")).isEqualTo(result.path("serverAnalysis"));
    }
}
