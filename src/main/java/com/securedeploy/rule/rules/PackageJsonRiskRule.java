package com.securedeploy.rule.rules;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.RuleMatch;
import com.securedeploy.rule.model.Severity;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

@Component
public class PackageJsonRiskRule implements VulnerabilityRule {

    private static final Pattern RISKY_SCRIPT = Pattern.compile("(?i)(curl|wget|rm\s+-rf|sudo|chmod\s+777)");
    private static final Pattern RISKY_PACKAGE = Pattern.compile("(?i)\"(event-stream|flatmap-stream|node-ipc|ua-parser-js|colors|faker)\"");

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isPackageJson(file)) {
            return List.of();
        }

        List<RuleMatch> matches = new ArrayList<>();
        List<String> lines = file.lines();
        for (int index = 0; index < lines.size(); index++) {
            String line = lines.get(index);
            if (RISKY_SCRIPT.matcher(line).find()) {
                matches.add(new RuleMatch(
                        "PACKAGE_JSON_RISK",
                        RuleCategory.DEPENDENCY,
                        Severity.MEDIUM,
                        file.relativePath(),
                        index + 1,
                        "package.json scripts에 위험할 수 있는 명령어가 포함되어 있습니다.",
                        "설치/빌드 script에서 원격 다운로드, 권한 변경, 삭제 명령을 사용하는 경우 공급망 공격 위험이 있으므로 필요성과 출처를 검토하세요.",
                        line.strip()
                ));
            } else if (RISKY_PACKAGE.matcher(line).find()) {
                matches.add(new RuleMatch(
                        "PACKAGE_JSON_RISK",
                        RuleCategory.DEPENDENCY,
                        Severity.LOW,
                        file.relativePath(),
                        index + 1,
                        "주의가 필요한 프론트엔드 의존성 후보가 발견되었습니다. 실제 CVE 여부는 별도 점검이 필요합니다.",
                        "npm audit, SCA 도구, lockfile 검증으로 현재 설치 버전의 취약점과 공급망 위험을 확인하세요.",
                        line.strip()
                ));
            }
        }
        return matches;
    }
}
