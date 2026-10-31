package com.securedeploy.release;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.*;
import static org.junit.jupiter.api.Assertions.*;
class RecoveryFilterTest {
 @Test void writesAndWorkspacesAreUnavailableButLoginAndResultReadsContinue()throws Exception{
  for(String[] test:new String[][]{{"GET","/api/projects","200"},{"POST","/api/auth/login","200"},{"POST","/api/reviews/upload","503"},{"POST","/%61pi/reviews/upload","503"},{"DELETE","/api/reviews/1","503"},{"GET","/api/editing-workspaces/id","503"},{"POST","/api/auth/signup","503"}}){
   var request=new MockHttpServletRequest(test[0],test[1]);var response=new MockHttpServletResponse();new RecoveryReadOnlyFilter().doFilter(request,response,new MockFilterChain());assertEquals(Integer.parseInt(test[2]),response.getStatus());
  }
 }
}
