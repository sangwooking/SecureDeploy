package com.securedeploy.evaluation;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;
import static org.assertj.core.api.Assertions.*;

class BenchmarkEngineRunnerTest {
    @TempDir Path temp;
    @BeforeEach void canonicalTemporaryRoot() throws Exception {temp=temp.toRealPath();}
    @Test void verifiesExactSourcesWithoutExecutingThem() throws Exception {
        String source="class Synthetic { static { throw new RuntimeException(); } }";
        Files.writeString(temp.resolve("Synthetic.java"),source);
        var manifest=new ObjectMapper().valueToTree(Map.of("files",List.of(Map.of("path","Synthetic.java","sha256",BenchmarkEngineRunner.hash(source.getBytes(java.nio.charset.StandardCharsets.UTF_8))))));
        assertThatCode(()->BenchmarkEngineRunner.verify(temp,manifest)).doesNotThrowAnyException();
        Files.writeString(temp.resolve("Synthetic.java"),"changed");
        assertThatThrownBy(()->BenchmarkEngineRunner.verify(temp,manifest)).hasMessage("SOURCE_HASH");
    }
    @Test void rejectsUnexpectedFilesAndSymlinks() throws Exception {
        var manifest=new ObjectMapper().valueToTree(Map.of("files",List.of()));
        Files.writeString(temp.resolve("unexpected.sh"),"never executed");
        assertThatThrownBy(()->BenchmarkEngineRunner.verify(temp,manifest)).hasMessage("UNEXPECTED_SOURCE_OR_SYMLINK");
        Files.delete(temp.resolve("unexpected.sh"));
        Files.createSymbolicLink(temp.resolve("link"),Path.of("/tmp"));
        assertThatThrownBy(()->BenchmarkEngineRunner.verify(temp,manifest)).hasMessage("UNEXPECTED_SOURCE_OR_SYMLINK");
    }
    @Test void rejectsOutsideRootEvenWhenReadable() throws Exception {
        var manifest=new ObjectMapper().valueToTree(Map.of("files",List.of(Map.of("path","../outside.java","sha256","x"))));
        assertThatThrownBy(()->BenchmarkEngineRunner.verify(temp,manifest)).hasMessage("SOURCE_PATH");
    }
}
