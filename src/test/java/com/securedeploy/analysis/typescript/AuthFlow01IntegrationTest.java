package com.securedeploy.analysis.typescript;
import org.junit.jupiter.api.Test;import java.util.*;import static org.junit.jupiter.api.Assertions.*;
class AuthFlow01IntegrationTest {
 @Test void mongodbEvidenceSurvivesBackendConversionWithoutInventingAuthorization()throws Exception{
 var r=new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties()).analyze(new WorkerV53IntegrationTest().project(Map.of("package.json","{\"type\":\"module\",\"dependencies\":{\"express\":\"5.1.0\",\"mongodb\":\"6.12.0\"}}","app.mjs","import express from 'express';import{MongoClient}from'mongodb';const app=express();const db=new MongoClient('mongodb://fixture.invalid').db('owned').collection('records');app.get('/r/:id',(req,res)=>{db.deleteOne({_id:req.params.id,holder:req.user.id});});")));
 assertEquals("ts-server-v61",r.analyzerVersion());var d=r.authorizationContexts().get(0).details();assertNotNull(d);assertEquals("UNKNOWN",d.authenticationStatus());assertEquals("OWNER_POLICY_REVIEW_REQUIRED",d.objectAuthorizationStatus());assertFalse(d.principalReferences().isEmpty());assertFalse(d.accesses().get(0).identifierInputs().isEmpty());assertTrue(r.validatedFindings().isEmpty());var c=new ServerAnalysisConverter();assertEquals(r,c.convertToEntityAttribute(c.convertToDatabaseColumn(r)));
 }
}
