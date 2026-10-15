package com.securedeploy.github.service;

import com.securedeploy.github.model.GitHubRepositoryUrl;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.*;
import org.eclipse.jgit.transport.http.HttpConnection;
import org.springframework.http.HttpStatus;

/** Anonymous TLS-only Git HTTP. No JVM cookies, authenticators, redirects, or proxy credentials. */
final class PublicGitHubConnection implements HttpConnection {
    private static final HttpClient CLIENT = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(10)).proxy(new ProxySelector() {
                public List<Proxy> select(URI uri) { return List.of(Proxy.NO_PROXY); }
                public void connectFailed(URI uri, SocketAddress address, IOException failure) { }
            }).build();
    private final URL url;
    private final HttpClient client;
    private final CloneBudget budget;
    private final Map<String, String> headers = new HashMap<>();
    private final ByteArrayOutputStream body = new ByteArrayOutputStream();
    private String method = "GET";
    private HttpResponse<InputStream> response;
    private InputStream input;

    PublicGitHubConnection(URL url, GitHubRepositoryUrl repository, CloneBudget budget) throws IOException {
        this(url, repository, budget, CLIENT);
    }
    PublicGitHubConnection(URL url, GitHubRepositoryUrl repository, CloneBudget budget, HttpClient client) throws IOException {
        String root = repository.cloneUrl();
        String target = url.toExternalForm();
        if (!target.equals(root + "/info/refs?service=git-upload-pack") && !target.equals(root + "/git-upload-pack")) {
            throw new IOException("Git endpoint rejected");
        }
        this.url = url; this.budget = budget; this.client = client;
    }
    private void send() throws IOException {
        if (response != null) return;
        budget.request();
        try {
            var request = HttpRequest.newBuilder(url.toURI()).timeout(Duration.ofMillis(budget.remainingMillis()));
            headers.forEach(request::header);
            request.header("Accept-Encoding", "identity");
            request.method(method, method.equals("POST") ? HttpRequest.BodyPublishers.ofByteArray(body.toByteArray()) : HttpRequest.BodyPublishers.noBody());
            var pending = client.sendAsync(request.build(), HttpResponse.BodyHandlers.ofInputStream());
            pending.thenAccept(value -> { try { budget.track(value.body()); } catch (Exception ignored) { try { value.body().close(); } catch (IOException ignoredClose) { } } });
            try { response = pending.get(budget.remainingMillis(), TimeUnit.MILLISECONDS); }
            catch (Exception failure) { pending.cancel(true); throw failure; }
            validateResponse(response.statusCode(), budget);
            String encoding = response.headers().firstValue("content-encoding").orElse("identity");
            if (!encoding.equalsIgnoreCase("identity")) throw new IOException("Unsupported HTTP encoding");
            input = new FilterInputStream(response.body()) {
                public int read() throws IOException { budget.check(); int n = super.read(); if (n >= 0) budget.downloaded(1); return n; }
                public int read(byte[] b, int off, int len) throws IOException { budget.check(); int n = in.read(b, off, len); budget.downloaded(n); return n; }
            };
            budget.check();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt(); throw new IOException("Git request interrupted");
        } catch (Exception failed) {
            Throwable cause = failed instanceof java.util.concurrent.ExecutionException ? failed.getCause() : failed;
            if (cause instanceof HttpTimeoutException || cause instanceof java.util.concurrent.TimeoutException) {
                throw budget.fail(HttpStatus.GATEWAY_TIMEOUT, "저장소를 가져오는 시간이 너무 오래 걸렸습니다.");
            }
            budget.check(); throw new IOException("Git request failed");
        }
    }
    static void validateResponse(int status, CloneBudget budget) {
        if (status == 401 || status == 403 || status == 404) throw budget.fail(HttpStatus.BAD_REQUEST,
                "저장소를 찾을 수 없거나 접근할 수 없습니다. 현재는 공개 GitHub 저장소만 지원합니다.");
        if (status >= 300 && status < 400) throw budget.fail(HttpStatus.BAD_REQUEST,
                "저장소 주소가 변경되었거나 redirect가 필요합니다. GitHub의 최종 공개 저장소 URL을 입력해 주세요.");
        if (status != 200) throw budget.fail(HttpStatus.BAD_GATEWAY,
                "GitHub에서 프로젝트를 가져오지 못했습니다. 잠시 후 다시 시도해 주세요.");
    }
    public int getResponseCode() throws IOException { send(); return response.statusCode(); }
    public URL getURL() { return url; }
    public String getResponseMessage() { return "GitHub response"; }
    public Map<String, List<String>> getHeaderFields() { return response == null ? Map.of() : response.headers().map(); }
    public String getHeaderField(String name) { return response == null ? null : response.headers().firstValue(name).orElse(null); }
    public List<String> getHeaderFields(String name) { return response == null ? List.of() : response.headers().allValues(name); }
    public String getContentType() { return getHeaderField("Content-Type"); }
    public int getContentLength() { return -1; }
    public InputStream getInputStream() throws IOException { send(); return input; }
    public void setRequestProperty(String name, String value) {
        // Config-supplied credentials, cookies, and custom host headers must never leave this process.
        String key = name.toLowerCase(Locale.ROOT);
        if (Set.of("accept", "content-type", "git-protocol", "user-agent").contains(key)
                || (key.equals("content-encoding") && value.equalsIgnoreCase("gzip"))) headers.put(key, value);
    }
    public void setRequestMethod(String value) throws ProtocolException {
        if (!Set.of("GET", "POST").contains(value)) throw new ProtocolException("Read-only Git only"); method = value;
    }
    public String getRequestMethod() { return method; }
    public OutputStream getOutputStream() {
        return new OutputStream() {
            public void write(int value) throws IOException {
                if (body.size() >= 1024 * 1024) throw new IOException("Git request size limit"); body.write(value);
            }
            public void write(byte[] bytes, int off, int len) throws IOException {
                if (len > 1024 * 1024 - body.size()) throw new IOException("Git request size limit"); body.write(bytes, off, len);
            }
        };
    }
    public boolean usingProxy() { return false; }
    public void connect() throws IOException { send(); }
    public void setUseCaches(boolean value) { }
    public void setConnectTimeout(int value) { }
    public void setReadTimeout(int value) { }
    public void setInstanceFollowRedirects(boolean value) { }
    public void setDoOutput(boolean value) { }
    public void setFixedLengthStreamingMode(int value) { }
    public void setChunkedStreamingMode(int value) { }
    public void setHostnameVerifier(HostnameVerifier verifier) { }
    public void configure(KeyManager[] keys, TrustManager[] trusts, java.security.SecureRandom random) { }
}
