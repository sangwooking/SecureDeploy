package com.securedeploy.analysis.typescript;

import com.securedeploy.project.model.*;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class ExpressFlowTest {
    final TypeScriptServerAnalyzer analyzer=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties());
    ServerAnalysisSnapshot analyze(String query,String manifest) {
        var sources=Map.of("server.cjs","const express=require('express');const {MongoClient}=require('mongodb');const app=express();MongoClient.connect('unused',(err,db)=>{const c=db.collection('items');app.get('/',(req,res)=>c.find("+query+").toArray());});",
                "package.json",manifest);
        var files=sources.entrySet().stream().map(e->new ProjectFile(Path.of(e.getKey()),e.getKey(),e.getKey().endsWith(".json")?ProjectFileType.PACKAGE_JSON:ProjectFileType.JAVASCRIPT,e.getValue().lines().toList())).toList();
        var result=analyzer.analyze(new ProjectStructure(Path.of("."),files));assertThat(result.status()).isEqualTo("PARTIAL");return result;
    }
    @Test void supportedMongoApiOriginDistinguishesExecutableWhereFromDataComparisonAndUnknownDriver() {
        String manifest="{\"dependencies\":{\"mongodb\":\"^2.2.0\",\"express\":\"^4.18.0\"}}";
        var risk=analyze("{$where:'this.amount > '+req.query.value}",manifest);
        assertThat(risk.nodeUses()).anyMatch(u->u.kind().equals("INPUT_TO_EXECUTION"));
        assertThat(risk.validatedFindings()).hasSize(1).allSatisfy(f->{
            assertThat(f.ruleId()).isEqualTo("JS_MONGO_WHERE_INPUT_FLOW");
            assertThat(f.priority().name()).isEqualTo("REVIEW_REQUIRED");assertThat(f.comparisonPolicy()).isEqualTo("NOT_COMPARED");
        });
        assertThat(analyze("{amount:req.query.value}",manifest).validatedFindings()).isEmpty();
        assertThat(analyze("{$where:'this.amount > '+parseInt(req.query.value,10)}",manifest).validatedFindings()).isEmpty();
        var unresolved=analyze("{$where:req.query.value}","{\"dependencies\":{\"mongodb\":\"latest\"}}");
        assertThat(unresolved.validatedFindings()).isEmpty();
        assertThat(unresolved.files()).anyMatch(f->f.limitations().contains("MONGODB_CONNECTION_API_VERSION_UNKNOWN"));
        var converter=new ServerAnalysisConverter();
        assertThat(converter.convertToEntityAttribute(converter.convertToDatabaseColumn(risk))).isEqualTo(risk);
        assertThat(converter.convertToDatabaseColumn(risk)).doesNotContain("this.amount");
    }
}
