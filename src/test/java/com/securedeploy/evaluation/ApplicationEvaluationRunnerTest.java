package com.securedeploy.evaluation;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import static org.assertj.core.api.Assertions.*;

class ApplicationEvaluationRunnerTest {
    @TempDir Path temp;
    @BeforeEach void canonical()throws Exception { temp=temp.toRealPath(); }
    @Test void verifiesTextHashWithoutExecutingTarget()throws Exception {
        Path source=Files.createDirectory(temp.resolve("source"));Path file=source.resolve("main.js");
        Files.writeString(file,"throw new Error('upstream must never execute');");
        var p=new ObjectMapper().valueToTree(Map.of("files",List.of(Map.of("path","main.js","sha256",BenchmarkEngineRunner.hash(Files.readAllBytes(file))))));
        ApplicationEvaluationRunner.verify(temp,source,p);
        Files.writeString(file,"changed");
        assertThatThrownBy(()->ApplicationEvaluationRunner.verify(temp,source,p)).hasMessageContaining("HASH");
    }
    @Test void rejectsUnlistedFilesAndLinks()throws Exception {
        Path source=Files.createDirectory(temp.resolve("source"));
        var p=new ObjectMapper().readTree("{\"files\":[]}");
        Files.writeString(source.resolve("extra.js"),"source");
        assertThatThrownBy(()->ApplicationEvaluationRunner.verify(temp,source,p)).hasMessageContaining("UNEXPECTED_SOURCE");
        Files.delete(source.resolve("extra.js"));Files.createSymbolicLink(source.resolve("alias"),temp);
        assertThatThrownBy(()->ApplicationEvaluationRunner.verify(temp,source,p)).hasMessageContaining("UNEXPECTED_SOURCE");
    }
    @Test void rejectsOutsideRoot()throws Exception {
        Path allowed=Files.createDirectory(temp.resolve("allowed"));
        var p=new ObjectMapper().readTree("{\"files\":[]}");
        assertThatThrownBy(()->ApplicationEvaluationRunner.verify(allowed,temp,p)).hasMessageContaining("IDENTITY");
    }
    @Test void canonicalFileSpellingStillRequiresTheExactContentHash()throws Exception {
        Path source=Files.createDirectory(temp.resolve("source"));Path file=source.resolve("MixedCase.js");
        Files.writeString(file,"static fixture, never executed");
        Assumptions.assumeTrue(Files.isRegularFile(source.resolve("mixedcase.js")),"Requires case-insensitive filesystem alias");
        var p=new ObjectMapper().valueToTree(Map.of("files",List.of(Map.of("path","mixedcase.js","sha256",BenchmarkEngineRunner.hash(Files.readAllBytes(file))))));
        ApplicationEvaluationRunner.verify(temp,source,p);
        var duplicate=new ObjectMapper().valueToTree(Map.of("files",List.of(
                Map.of("path","MixedCase.js","sha256",BenchmarkEngineRunner.hash(Files.readAllBytes(file))),
                Map.of("path","mixedcase.js","sha256",BenchmarkEngineRunner.hash(Files.readAllBytes(file))))));
        assertThatThrownBy(()->ApplicationEvaluationRunner.verify(temp,source,duplicate)).hasMessageContaining("HASH");
        Files.writeString(file,"changed");
        assertThatThrownBy(()->ApplicationEvaluationRunner.verify(temp,source,p)).hasMessageContaining("HASH");
    }
}
