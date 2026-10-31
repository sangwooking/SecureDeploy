package com.securedeploy.release;
import org.junit.jupiter.api.Test;import static org.junit.jupiter.api.Assertions.*;
class CompatibleOperationTest {
 @Test void manualFlowIsAvailableWhileAutomationCannotBeInvoked(){
  String id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",base="/api/editing-workspaces/"+id;
  for(String[] r:new String[][]{{"POST","/api/auth/login"},{"POST","/api/reviews/upload"},{"POST","/api/projects/1/reviews/upload"},{"POST","/api/editing-workspaces/github/1"},{"PUT",base+"/files/"+id},{"POST",base+"/export/zip"},{"POST",base+"/export/patch"},{"POST",base+"/scans"},{"GET",base+"/files/"+id+"/diff"},{"DELETE",base}})assertTrue(CompatibleOperationFilter.allowed(r[0],r[1]),r[1]);
  for(String path:new String[]{base+"/deterministic-patches",base+"/patch-plans",base+"/patches/id/generate",base+"/semantic-reviews/id/generate","/%61pi/reviews/upload","/api/reviews/1/dependency-ai/id/generate"})assertFalse(CompatibleOperationFilter.allowed("POST",path),path);
 }
}
