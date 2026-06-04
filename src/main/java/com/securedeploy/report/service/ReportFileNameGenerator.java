package com.securedeploy.report.service;

import org.springframework.stereotype.Component;

@Component
public class ReportFileNameGenerator {

    public String generate(Long reviewId) {
        return "securedeploy-report-" + reviewId + ".pdf";
    }

    public String generateAi(Long reviewId) {
        return "securedeploy-ai-report-" + reviewId + ".pdf";
    }
}
