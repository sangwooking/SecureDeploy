package com.securedeploy.analysis.typescript;

import com.securedeploy.project.model.*;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class SqlObjectFlowTest {
    ServerAnalysisSnapshot run(String body){
        var sources=Map.of("package.json","{\"dependencies\":{\"sequelize\":\"6.37.5\",\"express\":\"4.18.0\"}}",
            "server.cjs","const express=require('express');const E=require('sequelize');const db=new E('unused');const app=express();app.post('/',(req,res)=>{"+body+"});");
        var files=sources.entrySet().stream().map(e->new ProjectFile(Path.of(e.getKey()),e.getKey(),e.getKey().endsWith(".json")?ProjectFileType.PACKAGE_JSON:ProjectFileType.JAVASCRIPT,e.getValue().lines().toList())).toList();
        return new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties()).analyze(new ProjectStructure(Path.of("/not-executed"),files));
    }
    @Test void queryFieldNotValuesReachesFinalFindingAndBoundCounterpartRemainsSeparate(){
        var risk=run("db.query({query:'SELECT * FROM items WHERE id='+req.body.id});");
        assertThat(risk.validatedFindings()).hasSize(1).allSatisfy(f->{
            assertThat(f.ruleId()).isEqualTo("JS_SEQUELIZE_SQL_INPUT_FLOW");
            assertThat(f.priority().name()).isEqualTo("REVIEW_REQUIRED");
            assertThat(f.comparisonPolicy()).isEqualTo("NOT_COMPARED");
            assertThat(f.evidence().get(0).source().kind()).isEqualTo("EXPRESS_BODY");
        });
        var safe=run("db.query({query:'SELECT * FROM items WHERE id=$1',bind:[req.body.id]});");
        assertThat(safe.validatedFindings()).isEmpty();
        assertThat(safe.nodeUses()).anyMatch(u->u.kind().equals("STATIC_OR_DATA_ONLY"));
        var unknown=run("db.query({query:'SELECT * FROM items WHERE id='+req.body.id,values:[req.body.id],bind:[req.body.id]});");
        assertThat(unknown.validatedFindings()).isEmpty();
        assertThat(unknown.nodeUses()).anyMatch(u->u.kind().equals("FLOW_UNRESOLVED"));
        var converter=new ServerAnalysisConverter();String json=converter.convertToDatabaseColumn(risk);
        assertThat(converter.convertToEntityAttribute(json)).isEqualTo(risk);
        assertThat(json).doesNotContain("SELECT * FROM items");
    }
}
