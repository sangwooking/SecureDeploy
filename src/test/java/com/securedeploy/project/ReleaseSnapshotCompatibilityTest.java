package com.securedeploy.project;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import com.securedeploy.project.progress.*;
class ReleaseSnapshotCompatibilityTest {
 @Test void oldAndAdditiveSecurityUnknownSnapshotsNeverBecomeSafe(){
  var c=new ComparisonContextConverter();String old="{\"schemaVersion\":1,\"baselineReviewId\":null,\"analyzerVersion\":\"ts-server-v51\",\"ruleAnalysisComplete\":true,\"analyzedFiles\":[]}";
  assertEquals("ts-server-v51",c.convertToEntityAttribute(old).analyzerVersion());
  for(String future:java.util.List.of(old.replace(":1,",":99,"),old.replace("\"analyzedFiles\":[]","\"analyzedFiles\":[],\"unknownSecurityMeaning\":true"),"malformed")){
   var value=c.convertToEntityAttribute(future);assertFalse(value.ruleAnalysisComplete());assertNull(value.baselineReviewId());assertEquals("UNSUPPORTED_SNAPSHOT_REVIEW_REQUIRED",value.analyzerVersion());
  }
  var p=new ReviewProgressSnapshotConverter();var unsupported=p.convertToEntityAttribute("{\"comparisonSchemaVersion\":99,\"status\":\"FUTURE_SAFE\"}");assertEquals(ReviewProgressSnapshot.Status.UNAVAILABLE,unsupported.status());assertNull(unsupported.assessmentAfter());
 }
}
