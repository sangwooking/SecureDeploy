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
public class DangerousSqlRule implements VulnerabilityRule {

    private static final Pattern CREATE_NATIVE_QUERY_WITH_CONCAT = Pattern.compile("\\.createNativeQuery\\s*\\([^;]*\\+");
    private static final Pattern RAW_STATEMENT = Pattern.compile("\\b(?:createStatement|Statement)\\b");
    private static final Pattern PREPARE_STATEMENT_WITH_CONCAT = Pattern.compile("\\.prepareStatement\\s*\\([^;]*\\+");
    private static final Pattern SQL_CONCAT_KEYWORDS = Pattern.compile("(?i)\\b(select|insert|update|delete)\\b[^;]*\\+");

    @Override
    public List<RuleMatch> evaluate(ProjectFile file) {
        if (!RuleFileTypes.isJava(file)) {
            return List.of();
        }

        List<RuleMatch> matches = new ArrayList<>();
        List<String> lines = file.lines();

        for (int index = 0; index < lines.size(); index++) {
            String line = lines.get(index);
            if (isDangerousSql(line)) {
                matches.add(new RuleMatch(
                        "DANGEROUS_SQL",
                        RuleCategory.DATABASE,
                        Severity.HIGH,
                        file.relativePath(),
                        index + 1,
                        "SQL Injection 위험이 있는 SQL 사용 패턴이 발견되었습니다.",
                        "파라미터 바인딩, JPA Query Method 또는 안전한 PreparedStatement 사용을 권장합니다.",
                        line.strip()
                ));
            }
        }

        return matches;
    }

    private boolean isDangerousSql(String line) {
        return CREATE_NATIVE_QUERY_WITH_CONCAT.matcher(line).find()
                || RAW_STATEMENT.matcher(line).find()
                || PREPARE_STATEMENT_WITH_CONCAT.matcher(line).find()
                || SQL_CONCAT_KEYWORDS.matcher(line).find();
    }
}
