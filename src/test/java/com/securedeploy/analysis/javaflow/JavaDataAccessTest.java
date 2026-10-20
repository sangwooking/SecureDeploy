package com.securedeploy.analysis.javaflow;

import com.securedeploy.project.model.*;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class JavaDataAccessTest {
    final JavaSqlAnalyzer analyzer=new JavaSqlAnalyzer();
    Map<String,String> layers(String sql) {
        var sources=new LinkedHashMap<String,String>();
        sources.put("web/Endpoint.java","package demo.web; import org.springframework.web.bind.annotation.*; import demo.service.Gateway; @RestController class Endpoint {final Gateway gateway; Endpoint(Gateway gateway){this.gateway=gateway;} @GetMapping(\"/\") String inspect(@RequestParam String input){return gateway.search(input);}}");
        sources.put("service/Gateway.java","package demo.service; public interface Gateway {String search(String input);}");
        sources.put("service/GatewayImpl.java","package demo.service; import org.springframework.stereotype.Service; import demo.data.Store; @Service class GatewayImpl implements Gateway {final Store store; GatewayImpl(Store store){this.store=store;} public String search(String value){return store.lookup(value);}}");
        sources.put("data/Store.java","package demo.data; import org.springframework.stereotype.Repository; import org.springframework.jdbc.core.JdbcTemplate; @Repository public class Store { JdbcTemplate jdbc; String lookup(String value){"+sql+"return value;}}");
        return sources;
    }
    JavaSqlWorker.Result analyze(Map<String,String> sources) {
        var files=sources.entrySet().stream().map(e->new ProjectFile(Path.of(e.getKey()),e.getKey(),e.getKey().endsWith(".xml")?ProjectFileType.XML:ProjectFileType.JAVA,e.getValue().lines().toList())).toList();
        var result=analyzer.analyze(new ProjectStructure(Path.of("."),files));
        assertThat(result.status()).as(result.limitations().toString()).isEqualTo("PARTIAL");return result;
    }
    @Test void constructorInjectedUniqueInterfaceImplementationReachesJdbcRiskAndBinding() {
        var risk=analyze(layers("jdbc.queryForList(\"SELECT * FROM items WHERE name=\"+value);"));
        assertThat(risk.uses()).anyMatch(u->u.kind().equals("INPUT_IN_QUERY")&&u.location().filePath().equals("data/Store.java"));
        assertThat(risk.dataAccess()).filteredOn(a->a.status().equals("RESOLVED_CALL")).hasSize(2);
        var safe=analyze(layers("jdbc.queryForList(\"SELECT * FROM items WHERE name=?\",value);"));
        assertThat(safe.uses()).allMatch(u->u.kind().equals("PARAMETERIZED_QUERY"));
    }
    @Test void multipleBeansOverloadsAndConditionalImplementationsNeverPickArbitrarily() {
        var sources=layers("jdbc.queryForList(\"SELECT \"+value);");
        sources.put("service/Other.java","package demo.service; import org.springframework.stereotype.Service; @Service class Other implements Gateway {public String search(String input){return input;}}");
        assertThat(analyze(sources).uses()).isEmpty();
        sources.remove("service/Other.java");
        sources.put("service/GatewayImpl.java",sources.get("service/GatewayImpl.java").replace("@Service","@org.springframework.context.annotation.Profile(\"test\") @Service"));
        assertThat(analyze(sources).uses()).isEmpty();
        sources=layers("jdbc.queryForList(\"SELECT \"+value);");
        sources.put("data/Store.java",sources.get("data/Store.java").replace("return value;}}","return value;} String lookup(Object value){return null;}}"));
        assertThat(analyze(sources).uses()).isEmpty();
    }
    @Test void autowiredFieldAndUnrelatedSameNamesAreTypeScoped() {
        var sources=layers("jdbc.queryForList(\"SELECT \"+value);");
        sources.put("web/Endpoint.java",sources.get("web/Endpoint.java").replace("final Gateway gateway; Endpoint(Gateway gateway){this.gateway=gateway;}","@org.springframework.beans.factory.annotation.Autowired Gateway gateway;"));
        sources.put("unrelated/Store.java","package unrelated; class Store {String lookup(String value){return null;}}");
        assertThat(analyze(sources).uses()).anyMatch(u->u.kind().equals("INPUT_IN_QUERY"));
    }
    Map<String,String> mapper(String placeholder) {
        var sources=new LinkedHashMap<String,String>();
        sources.put("Endpoint.java","package demo; import org.springframework.web.bind.annotation.*; @RestController class Endpoint { @org.springframework.beans.factory.annotation.Autowired Mapper mapper; @GetMapping(\"/\") void inspect(@RequestParam String input){mapper.lookup(input);}}");
        sources.put("Mapper.java","package demo; interface Mapper {String lookup(@org.apache.ibatis.annotations.Param(\"value\") String value);}");
        sources.put("sql/queries.xml","<mapper namespace=\"demo.Mapper\"><select id=\"lookup\">SELECT * FROM items WHERE name="+placeholder+"</select></mapper>");return sources;
    }
    @Test void mapperXmlBoundValuesAndProvenSubstitutionsStayDistinct() {
        var safe=analyze(mapper("#{value}"));
        assertThat(safe.uses()).anyMatch(u->u.kind().equals("PARAMETERIZED_QUERY"));
        var risk=analyze(mapper("${value}"));
        assertThat(risk.uses()).anyMatch(u->u.kind().equals("INPUT_IN_QUERY")&&u.trace().stream().anyMatch(l->l.filePath().endsWith("queries.xml")));
        assertThat(analyzer.reconcile(List.of(),risk).snapshot().findings()).hasSize(1);
        var allow=mapper("${value}");allow.put("Endpoint.java",allow.get("Endpoint.java").replace("mapper.lookup(input)","if(!input.equals(\"name\"))return; mapper.lookup(input)"));
        assertThat(analyze(allow).uses()).noneMatch(u->u.kind().equals("INPUT_IN_QUERY"));
    }
    @Test void unknownTransformDynamicXmlAndDtdCannotBecomeSafeOrProvenRisk() {
        var transformed=mapper("${value}");transformed.put("Endpoint.java",transformed.get("Endpoint.java").replace("mapper.lookup(input)","mapper.lookup(unknown(input))"));
        assertThat(analyze(transformed).uses()).allMatch(u->u.kind().equals("UNRESOLVED_QUERY"));
        var dynamic=mapper("<if test=\"value != null\">${value}</if>");
        assertThat(analyze(dynamic).dataAccess()).anyMatch(a->a.status().equals("UNKNOWN"));
        var entity=mapper("&payload;");entity.put("sql/queries.xml","<!DOCTYPE mapper [<!ENTITY payload SYSTEM 'file:///this-must-never-be-read'>]>"+entity.get("sql/queries.xml"));
        var failure=analyze(entity);assertThat(failure.uses()).isEmpty();
        assertThat(failure.dataAccess()).anyMatch(a->a.status().equals("NOT_INSPECTED"));
        var standard=mapper("#{value}");standard.put("sql/queries.xml","<!DOCTYPE mapper PUBLIC '-//mybatis.org//DTD Mapper 3.0//EN' 'http://127.0.0.1:9/no-external-loading'>"+standard.get("sql/queries.xml"));
        assertThat(analyze(standard).uses()).anyMatch(u->u.kind().equals("PARAMETERIZED_QUERY"));
    }
    @Test void springDataJpaIsObservedAsContractNotAnInjectionFinding() {
        var sources=mapper("#{value}");sources.remove("sql/queries.xml");
        sources.put("Mapper.java","package demo; interface Mapper extends org.springframework.data.jpa.repository.JpaRepository<Object,Long> { @org.springframework.data.jpa.repository.Query(\"SELECT i FROM Item i WHERE i.name=?1\") String lookup(String value);}");
        var result=analyze(sources);assertThat(result.uses()).isEmpty();
        assertThat(result.dataAccess()).anyMatch(a->a.framework().equals("SPRING_DATA_JPA")&&a.status().equals("DECLARED_QUERY_CONTRACT"));
    }
    @Test void qualifiersMutationAndObjectTransformsDoNotProveAnExecution() {
        var qualified=layers("jdbc.queryForList(\"SELECT \"+value);");
        qualified.put("web/Endpoint.java",qualified.get("web/Endpoint.java").replace("Endpoint(Gateway gateway)","Endpoint(@org.springframework.beans.factory.annotation.Qualifier(\"chosen\") Gateway gateway)"));
        assertThat(analyze(qualified).uses()).isEmpty();
        var mutable=layers("jdbc.queryForList(\"SELECT \"+value);");
        mutable.put("web/Endpoint.java",mutable.get("web/Endpoint.java").replace("final Gateway","Gateway").replace("return gateway.search(input);","this.gateway=unknown(); return gateway.search(input);"));
        assertThat(analyze(mutable).uses()).isEmpty();
        var transform=layers("jdbc.queryForList(\"SELECT \"+value);");
        transform.put("web/Endpoint.java",transform.get("web/Endpoint.java").replace("gateway.search(input)","gateway.search(transform(input))"));
        assertThat(analyze(transform).uses()).anyMatch(u->u.kind().equals("UNRESOLVED_QUERY"));
    }
    @Test void annotatedMapperAndDuplicateParametersRemainConservative() {
        var sources=mapper("${value}");sources.remove("sql/queries.xml");
        sources.put("Mapper.java","package demo; @org.apache.ibatis.annotations.Mapper interface Mapper {@org.apache.ibatis.annotations.Select(\"SELECT ${value}\") String lookup(@org.apache.ibatis.annotations.Param(\"value\") String value);}");
        assertThat(analyze(sources).uses()).anyMatch(u->u.kind().equals("INPUT_IN_QUERY"));
        sources.put("Mapper.java",sources.get("Mapper.java").replace("SELECT ${value}","<script>SELECT ${value}</script>"));
        assertThat(analyze(sources).uses()).isEmpty();
        assertThat(analyze(sources).dataAccess()).anyMatch(a->a.status().equals("UNKNOWN"));
    }
    @Test void oldJsonSnapshotWithoutDeclarationsRemainsReadable() throws Exception {
        var mapper=new com.fasterxml.jackson.databind.ObjectMapper();
        var old=mapper.readValue("{\"version\":\"java-sql-v2\",\"status\":\"PARTIAL\",\"files\":[],\"methods\":[],\"uses\":[],\"limitations\":[]}",JavaSqlWorker.Result.class);
        assertThat(old.dataAccess()).isEmpty();assertThat(old.version()).isEqualTo("java-sql-v2");
    }
    @Test void renamedPairedAndUnknownVariationsPreserveBoundedDecisions() {
        int risks=0,safe=0,deferred=0;
        for(int variant=0;variant<3;variant++)for(String mode:List.of("RISK","SAFE","UNKNOWN")) {
            String value=mode.equals("UNKNOWN")?"external(value)":"value";
            String sql=mode.equals("SAFE")?"jdbc.queryForList(\"SELECT * FROM entries WHERE key=?\",value);":"jdbc.queryForList(\"SELECT * FROM entries WHERE key=\"+"+value+");";
            var sources=new LinkedHashMap<String,String>();
            for(var entry:layers(sql).entrySet())sources.put("module"+variant+"/"+entry.getKey(),entry.getValue().replace("Gateway","Access"+variant).replace("lookup","fetch"+variant));
            var result=analyze(sources);
            if(mode.equals("RISK")){assertThat(result.uses()).anyMatch(u->u.kind().equals("INPUT_IN_QUERY"));risks++;}
            if(mode.equals("SAFE")){assertThat(result.uses()).isNotEmpty().allMatch(u->u.kind().equals("PARAMETERIZED_QUERY"));safe++;}
            if(mode.equals("UNKNOWN")){assertThat(result.uses()).isNotEmpty().allMatch(u->u.kind().equals("UNRESOLVED_QUERY"));assertThat(analyzer.reconcile(List.of(),result).snapshot().findings()).isEmpty();deferred++;}
        }
        assertThat(risks).isEqualTo(3);assertThat(safe).isEqualTo(3);assertThat(deferred).isEqualTo(3);
    }
    @Test @org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable(named="JAVA_DATA_ACCESS_PUBLIC_DIR",matches=".+")
    void freshOfficialSpringGuideIsParsingNotAClaimOfRequestFlowSupport() throws Exception {
        var root=java.nio.file.Path.of(System.getenv("JAVA_DATA_ACCESS_PUBLIC_DIR"));
        var json=new com.fasterxml.jackson.databind.ObjectMapper();var receipt=json.readTree(root.resolve("receipt.json").toFile());
        var sources=new LinkedHashMap<String,String>();
        for(var file:receipt.path("files"))if(file.path("path").asText().endsWith(".java")) {
            var path=root.resolve(file.path("path").asText());byte[] bytes=java.nio.file.Files.readAllBytes(path);
            assertThat(java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes))).isEqualTo(file.path("sha256").asText());
            sources.put(file.path("path").asText(),new String(bytes,java.nio.charset.StandardCharsets.UTF_8));
        }
        var result=analyze(sources);assertThat(result.files()).hasSize(2).allMatch(f->f.parseStatus().equals("PARSED")&&f.entrypoints()==0);
        assertThat(result.uses()).isEmpty();assertThat(result.files()).anyMatch(f->f.sqlCallSites()>0);
        String output=System.getenv("JAVA_DATA_ACCESS_PUBLIC_OUTPUT");assertThat(output).isNotBlank();
        var target=java.nio.file.Path.of(output);assertThat(target).doesNotExist();
        json.writerWithDefaultPrettyPrinter().writeValue(target.toFile(),Map.of("commitSha",receipt.path("commitSha").asText(),"analysis",result,"interpretation","CommandLineRunner entry is NOT_SUPPORTED; zero SQL flows is not a safe-project result","targetExecuted",false));
    }
}
