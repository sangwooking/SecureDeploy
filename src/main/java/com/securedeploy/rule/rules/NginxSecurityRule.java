package com.securedeploy.rule.rules;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.RuleMatch;
import com.securedeploy.rule.model.Severity;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.springframework.stereotype.Component;

@Component
public class NginxSecurityRule implements VulnerabilityRule {

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isNginx(file)) {
            return List.of();
        }

        List<RuleMatch> matches = new ArrayList<>();
        boolean hasHttpListen = false;
        boolean hasHttpsListen = false;
        boolean hasHttpsRedirect = false;
        List<String> lines = file.lines();

        for (int index = 0; index < lines.size(); index++) {
            String line = lines.get(index);
            String lower = line.toLowerCase(Locale.ROOT).strip();
            if (lower.matches("listen\s+80[;\s].*")) {
                hasHttpListen = true;
            }
            if (lower.matches("listen\s+443[;\s].*") || lower.contains("ssl")) {
                hasHttpsListen = true;
            }
            if (lower.contains("return 301 https://") || lower.contains("return 308 https://")) {
                hasHttpsRedirect = true;
            }
            if (lower.matches("autoindex\s+on;.*")) {
                matches.add(new RuleMatch(
                        "NGINX_DIRECTORY_LISTING",
                        RuleCategory.DEVOPS_SECURITY,
                        Severity.MEDIUM,
                        file.relativePath(),
                        index + 1,
                        "Nginx autoindex on 설정이 발견되었습니다. 디렉터리 목록이 노출될 수 있습니다.",
                        "정적 파일 디렉터리 listing이 필요하지 않다면 autoindex off를 사용하세요.",
                        line.strip()
                ));
            }
            if (lower.matches("server_tokens\s+on;.*")) {
                matches.add(new RuleMatch(
                        "NGINX_SERVER_TOKENS",
                        RuleCategory.DEVOPS_SECURITY,
                        Severity.LOW,
                        file.relativePath(),
                        index + 1,
                        "Nginx server_tokens on 설정이 발견되었습니다. 서버 버전 정보가 노출될 수 있습니다.",
                        "server_tokens off를 설정하여 버전 정보 노출을 줄이세요.",
                        line.strip()
                ));
            }
        }

        if (hasHttpListen && !hasHttpsListen && !hasHttpsRedirect) {
            matches.add(new RuleMatch(
                    "NGINX_HTTP_ONLY",
                    RuleCategory.DEVOPS_SECURITY,
                    Severity.MEDIUM,
                    file.relativePath(),
                    1,
                    "Nginx 설정이 HTTP listen만 포함하고 HTTPS 리다이렉트 또는 TLS 설정이 보이지 않습니다.",
                    "운영 환경에서는 TLS listen 443과 HTTP to HTTPS redirect를 구성하세요.",
                    "listen 80 without HTTPS redirect"
            ));
        }
        return matches;
    }
}
