package com.securedeploy.ai.controller;

import com.securedeploy.ai.dto.AiPriorityResponse;
import com.securedeploy.ai.dto.AiProjectSummaryResponse;
import com.securedeploy.ai.dto.AiRemediationResultResponse;
import com.securedeploy.ai.dto.AiReviewResultResponse;
import com.securedeploy.ai.dto.AiSecurityAuditResponse;
import com.securedeploy.ai.dto.AiSecurityRoadmapResponse;
import com.securedeploy.ai.service.AiReviewService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/reviews")
public class AiReviewController {

    private final AiReviewService aiReviewService;

    public AiReviewController(AiReviewService aiReviewService) {
        this.aiReviewService = aiReviewService;
    }

    @GetMapping("/{reviewId}/ai-review")
    public ResponseEntity<AiReviewResultResponse> generateAiReview(@PathVariable Long reviewId) {
        return ResponseEntity.ok(aiReviewService.generateReview(reviewId));
    }

    @GetMapping("/{reviewId}/ai-summary")
    public ResponseEntity<AiProjectSummaryResponse> generateAiSummary(@PathVariable Long reviewId) {
        return ResponseEntity.ok(aiReviewService.generateProjectSummary(reviewId));
    }

    @GetMapping("/{reviewId}/ai-remediation")
    public ResponseEntity<AiRemediationResultResponse> generateAiRemediation(@PathVariable Long reviewId) {
        return ResponseEntity.ok(aiReviewService.generateRemediationSuggestions(reviewId));
    }

    @GetMapping("/{reviewId}/ai-priorities")
    public ResponseEntity<AiPriorityResponse> generateAiPriorities(@PathVariable Long reviewId) {
        return ResponseEntity.ok(aiReviewService.generatePriorities(reviewId));
    }

    @GetMapping("/{reviewId}/ai-roadmap")
    public ResponseEntity<AiSecurityRoadmapResponse> generateAiRoadmap(@PathVariable Long reviewId) {
        return ResponseEntity.ok(aiReviewService.generateSecurityRoadmap(reviewId));
    }

    @GetMapping("/{reviewId}/ai-audit")
    public ResponseEntity<AiSecurityAuditResponse> generateAiAudit(@PathVariable Long reviewId) {
        return ResponseEntity.ok(aiReviewService.generateSecurityAudit(reviewId));
    }
}
