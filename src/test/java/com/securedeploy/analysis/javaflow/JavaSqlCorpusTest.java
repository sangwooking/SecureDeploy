package com.securedeploy.analysis.javaflow;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.project.model.*;
import com.securedeploy.rule.rules.DangerousSqlRule;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import static org.assertj.core.api.Assertions.assertThat;

/** Explicit local, public-source opt-in. No download or target compilation. */
class JavaSqlCorpusTest {
    @Test @EnabledIfEnvironmentVariable(named="JAVA_SQL_EVALUATION_DIR",matches=".+")
    void recordFrozenPublicTruthWithoutChangingTheEngineToPass() throws Exception {
        Path root=Path.of(System.getenv("JAVA_SQL_EVALUATION_DIR"));
        var mapper=new ObjectMapper();var manifest=mapper.readTree(root.resolve("manifest.json").toFile());
        String selection=System.getenv().getOrDefault("JAVA_SQL_EVALUATION_SET","regression");
        var rows=new ArrayList<Object>();var analyzer=new JavaSqlAnalyzer();
        for(var item:manifest.path("cases"))if(item.path("set").asText().equals(selection)) {
            String name=item.path("id").asText();assertThat(name).matches("BenchmarkTest[0-9]{5}");
            Path file=root.resolve(name+".java");
            assertThat(HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file))))
                    .as("Frozen upstream source hash").isEqualTo(item.path("sha256").asText());
            var input=new ProjectFile(file,name+".java",ProjectFileType.JAVA,Files.readAllLines(file));
            var project=new ProjectStructure(root,List.of(input));
            var raw=new DangerousSqlRule().evaluate(input);long start=System.nanoTime();
            var parsed=analyzer.analyze(project);var outcome=analyzer.reconcile(raw,parsed);
            assertThat(parsed.status()).isEqualTo("PARTIAL");
            rows.add(Map.of("id",name,"truth",item.path("truth").asText(),"rawWarnings",raw.size(),
                    "structuralRisks",parsed.uses().stream().filter(u->u.kind().equals("INPUT_IN_QUERY")).count(),
                    "finalWarnings",outcome.matches().size()+outcome.snapshot().findings().size(),
                    "snapshot",outcome.snapshot(),"elapsedMs",(System.nanoTime()-start)/1_000_000));
        }
        String file=System.getenv("JAVA_SQL_EVALUATION_OUTPUT");assertThat(file).isNotBlank();
        Path output=Path.of(file);assertThat(output).doesNotExist();
        mapper.writerWithDefaultPrettyPrinter().writeValue(output.toFile(),rows);
        assertThat(rows).hasSize(12);
    }
}
