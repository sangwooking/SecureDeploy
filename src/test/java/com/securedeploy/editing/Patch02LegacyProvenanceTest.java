package com.securedeploy.editing;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class Patch02LegacyProvenanceTest {
 @Test void olderSnapshotsRemainReadableWithoutInventingProviderOrApproval()throws Exception {
  var mapper=new ObjectMapper().findAndRegisterModules();String old="{\"schemaVersion\":1,\"workspaceId\":\"old\",\"userId\":1,\"originalReviewId\":1,\"revision\":2,\"sourceRevision\":\"legacy\",\"identityStatus\":\"UNVERIFIED_REUPLOAD\",\"inputHash\":\"old\",\"capturedAt\":null,\"analyzerVersion\":\"ts-server-v51\",\"baselineVerified\":false,\"files\":[{\"fileId\":\"x\",\"path\":\"old.js\",\"originalHash\":\"before\",\"currentHash\":\"after\",\"changed\":true,\"changeOrigin\":\"AI_APPROVED\"}],\"analysisRoot\":\"\"}";
  var value=mapper.readValue(old,WorkspaceScanSnapshot.class);assertTrue(value.files().get(0).provenance().isEmpty());assertTrue(value.exports().isEmpty());assertEquals("AI_APPROVED",value.files().get(0).changeOrigin());assertEquals(value,mapper.readValue(mapper.writeValueAsString(value),WorkspaceScanSnapshot.class));
 }
}
