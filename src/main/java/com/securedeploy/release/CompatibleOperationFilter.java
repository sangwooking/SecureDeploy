package com.securedeploy.release;
import jakarta.servlet.*;import jakarta.servlet.http.*;import java.io.IOException;
import org.springframework.context.annotation.Profile;import org.springframework.core.annotation.Order;import org.springframework.stereotype.Component;import org.springframework.web.filter.OncePerRequestFilter;
/** Functional fallback: explicit legacy writes only, independent of feature button visibility. */
@Component @Profile("release-compatible") @Order(org.springframework.core.Ordered.HIGHEST_PRECEDENCE+21)
public class CompatibleOperationFilter extends OncePerRequestFilter {
 public static boolean allowed(String method,String path){
  if(java.util.Set.of("GET","HEAD","OPTIONS").contains(method))return !path.matches(".*(?:ai-report|report/ai)(?:/.*)?");
  if(method.equals("POST")&&(path.matches("/api/auth/(?:login|signup)")||path.matches("/api/reviews/(?:upload|github)")||path.matches("/api/projects/[0-9]+/reviews/(?:upload|github)")))return true;
  if(method.equals("DELETE")&&path.matches("/api/(?:projects|reviews)/[0-9]+"))return true;
  if((method.equals("PUT")||method.equals("PATCH"))&&path.matches("/api/vulnerabilities/[0-9]+/status"))return true;
  String base="/api/editing-workspaces/",id="[0-9a-f-]{36}";
  if(method.equals("POST")&&(path.matches(base+"(?:zip|github)/[0-9]+")||path.matches(base+id+"/(?:export/(?:zip|patch)|scans|fix-options)")||path.matches(base+id+"/files/"+id+"/revert")))return true;
  return method.equals("PUT")&&path.matches(base+id+"/files/"+id)||method.equals("DELETE")&&path.matches(base+id);
 }
 @Override protected void doFilterInternal(HttpServletRequest req,HttpServletResponse res,FilterChain chain)throws ServletException,IOException{
  if(!allowed(req.getMethod(),req.getRequestURI())){res.setStatus(503);res.setContentType("application/json;charset=UTF-8");res.getWriter().write("{\"code\":\"COMPATIBLE_MANUAL_ONLY\",\"message\":\"호환 운영 모드입니다. 새 분석과 수동 편집·승인·재검사를 사용해 주세요.\"}");return;}
  res.setHeader("X-SecureDeploy-Recovery","COMPATIBLE_MANUAL_OPERATION");chain.doFilter(req,res);
 }
}
