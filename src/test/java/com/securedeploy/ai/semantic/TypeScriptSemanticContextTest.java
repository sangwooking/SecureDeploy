package com.securedeploy.ai.semantic;
import com.securedeploy.ai.remediation.RemediationSanitizer;
import com.securedeploy.analysis.typescript.*;
import com.securedeploy.project.model.*;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class TypeScriptSemanticContextTest {
 @Test void actualWorkerParserAndSharedValidatorAgreeWithoutChangingSource(){
  String code="const express=require('express');const app=express();const exec=require('node:child_process').exec;app.post('/work',(req,res)=>{/* do not forward me */const key='private-person@example.invalid';exec(transform(req.body.value));});";
  var p=new ProjectStructure(Path.of("/no-execution"),List.of(new ProjectFile(Path.of("server.ts"),"server.ts",ProjectFileType.TYPESCRIPT,code.lines().toList()),new ProjectFile(Path.of("package.json"),"package.json",ProjectFileType.PACKAGE_JSON,List.of("{\"dependencies\":{\"express\":\"4.21.2\"}}"))));
  var analysis=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties()).analyze(p);var selector=new TypeScriptSemanticContextSelector(new TypeScriptAnalysisProperties(),new SemanticProperties(),new SemanticSanitizer(new RemediationSanitizer()));
  var selected=selector.select(analysis,List.of(new TypeScriptSemanticContextSelector.Source("server.ts",code,"hash")));assertEquals(1,selected.slices().size());var slice=selected.slices().get(0);assertFalse(slice.toString().contains("private-person"));assertFalse(slice.toString().contains("do not forward"));assertTrue(slice.contexts().get(0).content().contains("transform"));
  assertTrue(analysis.nodeUses().stream().anyMatch(n->n.kind().equals("FLOW_UNRESOLVED")));assertTrue(selected.limitations().contains("OTHER_UNKNOWN_FILES_NOT_REVIEWED"));
 }
}
