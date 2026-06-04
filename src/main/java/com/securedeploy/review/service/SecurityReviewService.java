package com.securedeploy.review.service;

import com.securedeploy.review.dto.SecurityReviewResponse;
import com.securedeploy.review.dto.VulnerabilityResultResponse;
import com.securedeploy.rule.model.RuleMatch;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class SecurityReviewService {

    public SecurityReviewResponse createResponse(String projectName, int scannedFileCount, List<RuleMatch> matches) {
        int securityScore = calculateSecurityScore(matches);
        return new SecurityReviewResponse(
                null,
                null,
                projectName,
                scannedFileCount,
                matches.size(),
                securityScore,
                resolveDeploymentStatus(securityScore),
                matches.stream().map(VulnerabilityResultResponse::from).toList()
        );
    }

    private int calculateSecurityScore(List<RuleMatch> matches) {
        int penalty = matches.stream()
                .mapToInt(match -> switch (match.severity()) {
                    case LOW -> 3;
                    case MEDIUM -> 7;
                    case HIGH -> 14;
                    case CRITICAL -> 25;
                })
                .sum();

        return Math.max(0, 100 - penalty);
    }

    private String resolveDeploymentStatus(int securityScore) {
        if (securityScore >= 80) {
            return "배포 가능";
        }
        if (securityScore >= 60) {
            return "주의 필요";
        }
        return "배포 비권장";
    }
}
