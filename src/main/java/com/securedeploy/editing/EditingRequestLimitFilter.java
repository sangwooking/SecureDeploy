package com.securedeploy.editing;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.*;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** Bound JSON before Jackson allocation, including requests with chunked transfer encoding. */
@Component
public class EditingRequestLimitFilter extends OncePerRequestFilter {
    @Override protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/editing-workspaces/");
    }
    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        response.setHeader("Cache-Control", "no-store");
        String type = request.getContentType() == null ? "" : request.getContentType().split(";",2)[0].trim().toLowerCase(java.util.Locale.ROOT);
        if (!type.equals("application/json") && !(type.startsWith("application/") && type.endsWith("+json"))) { chain.doFilter(request, response); return; }
        if (request.getContentLengthLong() > 1024 * 1024) { reject(response); return; }
        // JSON input is bounded independently of untrusted Content-Length.
        byte[] body = request.getInputStream().readNBytes(1024 * 1024 + 1);
        if (body.length > 1024 * 1024) { reject(response); return; }
        chain.doFilter(new HttpServletRequestWrapper(request) {
            @Override public ServletInputStream getInputStream() {
                var input = new ByteArrayInputStream(body);
                return new ServletInputStream() {
                    public int read() { return input.read(); }
                    public int read(byte[] b, int off, int len) { return input.read(b, off, len); }
                    public boolean isFinished() { return input.available() == 0; }
                    public boolean isReady() { return true; }
                    public void setReadListener(ReadListener listener) { throw new UnsupportedOperationException(); }
                };
            }
            @Override public BufferedReader getReader() { return new BufferedReader(new InputStreamReader(getInputStream(), java.nio.charset.StandardCharsets.UTF_8)); }
        }, response);
    }
    private void reject(HttpServletResponse response) throws IOException {
        response.setStatus(413); response.setContentType("application/json;charset=UTF-8");
        response.setHeader("Cache-Control", "no-store");
        response.getWriter().write("{\"message\":\"수정 요청 크기 제한을 초과했습니다.\"}");
    }
}
