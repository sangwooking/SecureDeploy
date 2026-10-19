package com.securedeploy.rule.rules;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.rule.model.RuleCategory;
import com.securedeploy.rule.model.RuleMatch;
import com.securedeploy.rule.model.Severity;
import java.util.List;
import org.springframework.stereotype.Component;

@Component
public class StacktraceExposureRule implements VulnerabilityRule {

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isConfiguration(file)) {
            return List.of();
        }

        return ConfigFileParser.parse(file).stream()
                .filter(entry -> "server.error.include.stacktrace".equals(entry.normalizedKey()))
                .filter(entry -> "always".equalsIgnoreCase(entry.value()))
                .map(entry -> new RuleMatch(
                        "STACKTRACE_EXPOSURE",
                        RuleCategory.CONFIGURATION,
                        Severity.MEDIUM,
                        file.relativePath(),
                        entry.line(),
                        "오류 응답에 stacktrace를 항상 포함하는 설정 선언이 있습니다. 실제 운영 적용 여부를 확인하세요.",
                        "운영 설정은 server.error.include-stacktrace=never로 지정하고 일반 오류 메시지와 추적 ID만 반환하세요. 상세 정보는 접근이 제한된 내부 로그로 분리한 뒤 로컬 오류 응답 테스트와 재검사를 수행하세요.",
                        entry.evidence()
                ))
                .toList();
    }
}
