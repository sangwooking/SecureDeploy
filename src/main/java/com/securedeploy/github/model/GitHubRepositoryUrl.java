package com.securedeploy.github.model;

import com.securedeploy.global.error.SecureDeployException;
import java.net.URI;
import java.util.Locale;
import org.springframework.http.HttpStatus;

public record GitHubRepositoryUrl(String owner, String repository) {
    public static GitHubRepositoryUrl parse(String input) {
        try {
            URI uri = new URI(input == null ? "" : input.strip());
            if (!"https".equalsIgnoreCase(uri.getScheme()) || !"github.com".equalsIgnoreCase(uri.getHost())
                    || uri.getRawUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null
                    || (uri.getPort() != -1 && uri.getPort() != 443) || uri.getRawPath().contains("%")) throw new IllegalArgumentException();
            String[] parts = uri.getRawPath().replaceFirst("/$", "").split("/", -1);
            if (parts.length != 3 || !parts[0].isEmpty()) throw new IllegalArgumentException();
            String owner = parts[1].toLowerCase(Locale.ROOT);
            String repo = parts[2].replaceFirst("(?i)\\.git$", "").toLowerCase(Locale.ROOT);
            if (!owner.matches("[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?") || owner.contains("--")
                    || !repo.matches("[a-z0-9_.-]{1,100}") || repo.equals(".") || repo.equals("..")) throw new IllegalArgumentException();
            return new GitHubRepositoryUrl(owner, repo);
        } catch (Exception invalid) {
            throw new SecureDeployException(HttpStatus.BAD_REQUEST,
                    "GitHub 주소 형식이 올바르지 않습니다. https://github.com/owner/repository 형식의 공개 저장소 URL을 입력해 주세요.");
        }
    }
    public String canonicalUrl() { return "https://github.com/" + owner + "/" + repository; }
    public String cloneUrl() { return canonicalUrl() + ".git"; }
}
