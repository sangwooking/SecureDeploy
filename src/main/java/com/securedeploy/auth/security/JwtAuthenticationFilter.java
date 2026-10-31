package com.securedeploy.auth.security;

import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.persistence.entity.UserEntity;
import com.securedeploy.persistence.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;

    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider, UserRepository userRepository) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String authorization = request.getHeader("Authorization");
        if (authorization != null && authorization.startsWith("Bearer ")) {
            try {
                authenticate(authorization.substring(7));
            } catch (org.springframework.dao.DataAccessException | org.springframework.transaction.TransactionException unavailable) {
                SecurityContextHolder.clearContext();
                response.setStatus(HttpStatus.SERVICE_UNAVAILABLE.value());
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);response.setCharacterEncoding("UTF-8");
                response.getWriter().write("{\"status\":503,\"code\":\"AUTH_STORE_UNAVAILABLE\",\"message\":\"인증 저장소에 일시적으로 연결할 수 없습니다. 미저장 편집을 보관하고 연결 복구 후 저장 상태를 확인해 주세요.\"}");return;
            } catch (SecureDeployException exception) {
                writeUnauthorized(response, exception.getMessage());
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    private void writeUnauthorized(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("{\"timestamp\":\"" + LocalDateTime.now() + "\",\"status\":401,\"error\":\"Unauthorized\",\"message\":\"" + escape(message) + "\"}");
    }

    private String escape(String value) {
        return value == null ? "" : value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private void authenticate(String token) {
        Long userId = jwtTokenProvider.extractUserId(token);
        UserEntity user = userRepository.findById(userId).orElse(null);
        if (user == null) {
            SecurityContextHolder.clearContext();
            return;
        }

        AuthenticatedUser principal = new AuthenticatedUser(user.getId(), user.getEmail(), user.getName());
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(principal, null, List.of());
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
