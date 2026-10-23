package com.securedeploy.analysis.typescript;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.review.service.SecurityReviewFacade;
import java.nio.file.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.mock.web.MockMultipartFile;
import java.io.ByteArrayOutputStream;
import java.util.zip.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(properties={"securedeploy.ai.provider=TEMPLATE","securedeploy.sca.enabled=false","securedeploy.threat-intelligence.enabled=false"})
@AutoConfigureMockMvc
class PreBetaExposureIntegrationTest {
    @Autowired SecurityReviewFacade facade;
    @Autowired ObjectMapper mapper;
    @Autowired MockMvc mvc;
    @TempDir Path root;

    @Test void newSourcesAndSinksReachProductFindingsWithoutChangingLegacyScoreOrRules() throws Exception {
        String token=mapper.readTree(mvc.perform(post("/api/auth/signup").contentType("application/json").content(mapper.writeValueAsBytes(java.util.Map.of(
                "email",java.util.UUID.randomUUID()+"@prebeta.invalid","name","synthetic","password","Synthetic-Local-813!"))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray()).path("accessToken").asText();
        for(String framework:new String[]{"deno","express","next"}) {
            Path project=Files.createDirectory(root.resolve(framework));
            boolean express=framework.equals("express"),next=framework.equals("next");
            String path=express?"server.cjs":next?"app/api/test/route.ts":"supabase/functions/test/index.ts";
            if(express||next)Files.writeString(project.resolve("package.json"),express?"{\"dependencies\":{\"express\":\"4.18.0\"}}":"{\"dependencies\":{\"next\":\"14.2.0\"}}");
            Path file=project.resolve(path);Files.createDirectories(file.getParent());
            String body=express?"response.json({value:process.env.API_SECRET});":next?"console.log(process.env.API_SECRET);return Response.json({ready:true});":"console.log(Deno.env.get('API_SECRET'));return Response.json({ready:true});";
            String prefix=express?"const express=require('express');const app=express();app.get('/inspect',(request,response)=>{":next?"export async function GET(request){":"Deno.serve(async request=>{";
            String suffix=next?"}":"});";
            Files.writeString(file,prefix+body+suffix);
            var risk=facade.analyzeWorkspace("synthetic-prebeta",project).response();
            assertEquals(1,risk.serverAnalysis().validatedFindings().size());
            var finding=risk.serverAnalysis().validatedFindings().get(0);
            assertEquals("TS_SENSITIVE_DATA_EXPOSURE",finding.ruleId());
            assertEquals(express?"EXPRESS_HTTP_RESPONSE":"LOG_ARGUMENT",finding.location().kind());
            assertEquals("REVIEW_REQUIRED",finding.priority().name());assertEquals("NOT_COMPARED",finding.comparisonPolicy());
            assertEquals(path,finding.location().filePath());assertFalse(finding.evidence().isEmpty());
            String serialized=new ServerAnalysisConverter().convertToDatabaseColumn(risk.serverAnalysis());
            assertFalse(serialized.contains("API_SECRET"));assertFalse(serialized.contains("process.env"));
            assertEquals(risk.serverAnalysis(),new ServerAnalysisConverter().convertToEntityAttribute(serialized));
            var savedRisk=upload(project,token);
            Files.writeString(file,prefix+(express?"response.json({ready:true});":"return Response.json({ready:true});")+suffix);
            var normal=facade.analyzeWorkspace("synthetic-prebeta",project).response();
            assertTrue(normal.serverAnalysis().validatedFindings().isEmpty());
            assertEquals(normal.securityScore(),risk.securityScore());
            assertEquals(mapper.valueToTree(normal.vulnerabilities()),mapper.valueToTree(risk.vulnerabilities()));
            var savedNormal=upload(project,token);
            assertFalse(savedRisk.path("riskAssessment").isNull());
            assertEquals(savedNormal.at("/riskAssessment/prioritySummary"),savedRisk.at("/riskAssessment/prioritySummary"));
            assertEquals(savedNormal.path("securityScore"),savedRisk.path("securityScore"));
            assertEquals(1,savedRisk.at("/serverAnalysis/validatedFindings").size());
            var old=mapper.readTree(mvc.perform(get("/api/reviews/"+savedRisk.path("reviewId").asLong()).header("Authorization","Bearer "+token))
                    .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
            assertEquals(savedRisk,old);
        }
    }
    private com.fasterxml.jackson.databind.JsonNode upload(Path root,String token) throws Exception {
        var bytes=new ByteArrayOutputStream();
        try(var zip=new ZipOutputStream(bytes);var paths=Files.walk(root)) {
            for(var file:paths.filter(Files::isRegularFile).sorted().toList()) {
                zip.putNextEntry(new ZipEntry(root.relativize(file).toString().replace('\\','/')));zip.write(Files.readAllBytes(file));zip.closeEntry();
            }
        }
        return mapper.readTree(mvc.perform(multipart("/api/reviews/upload").file(new MockMultipartFile("file","synthetic.zip","application/zip",bytes.toByteArray()))
                .header("Authorization","Bearer "+token)).andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
    }
}
