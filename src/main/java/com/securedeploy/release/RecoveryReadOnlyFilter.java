package com.securedeploy.release;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** Same-version recovery: query existing results only, never resume unsupported/durable edits. */
@Component @Profile("release-recovery") @Order(org.springframework.core.Ordered.HIGHEST_PRECEDENCE+20)
public class RecoveryReadOnlyFilter extends OncePerRequestFilter {
    @Override protected void doFilterInternal(HttpServletRequest req,HttpServletResponse res,FilterChain chain)throws ServletException,IOException{
        String path=req.getRequestURI();
        boolean login=path.equals("/api/auth/login")&&req.getMethod().equals("POST");
        boolean read=req.getMethod().equals("GET")||req.getMethod().equals("HEAD")||req.getMethod().equals("OPTIONS");
        if(path.startsWith("/api/")&&(!read&&!login||path.startsWith("/api/editing-workspaces"))){
            res.setStatus(503);res.setContentType("application/json;charset=UTF-8");
            res.getWriter().write("{\"code\":\"RECOVERY_READ_ONLY\",\"message\":\"읽기 전용 복구 모드입니다. 저장된 결과만 조회할 수 있습니다.\"}");return;
        }
        res.setHeader("X-SecureDeploy-Recovery","READ_ONLY");chain.doFilter(req,res);
    }
}
