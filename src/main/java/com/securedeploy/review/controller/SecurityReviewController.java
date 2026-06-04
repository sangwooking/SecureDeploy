package com.securedeploy.review.controller;

import com.securedeploy.github.dto.GithubRepositoryReviewRequest;
import com.securedeploy.auth.service.CurrentUserService;
import com.securedeploy.global.dto.DeleteResponse;
import com.securedeploy.review.dto.ReviewHistoryResponse;
import com.securedeploy.review.dto.SecurityReviewResponse;
import com.securedeploy.review.service.SecurityReviewFacade;
import com.securedeploy.review.service.ReviewDeleteService;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/reviews")
public class SecurityReviewController {

    private final SecurityReviewFacade securityReviewFacade;
    private final ReviewDeleteService reviewDeleteService;
    private final CurrentUserService currentUserService;

    public SecurityReviewController(SecurityReviewFacade securityReviewFacade, ReviewDeleteService reviewDeleteService,
                                    CurrentUserService currentUserService) {
        this.securityReviewFacade = securityReviewFacade;
        this.reviewDeleteService = reviewDeleteService;
        this.currentUserService = currentUserService;
    }

    @GetMapping
    public ResponseEntity<List<ReviewHistoryResponse>> findReviewHistories() {
        return ResponseEntity.ok(securityReviewFacade.findReviewHistories());
    }

    @GetMapping("/{reviewId}")
    public ResponseEntity<SecurityReviewResponse> findReviewDetail(@PathVariable Long reviewId) {
        return ResponseEntity.ok(securityReviewFacade.findReviewDetail(reviewId));
    }

    @DeleteMapping("/{reviewId}")
    public ResponseEntity<DeleteResponse> deleteReview(@PathVariable Long reviewId) {
        reviewDeleteService.deleteReview(reviewId, currentUserService.currentUserId());
        return ResponseEntity.ok(new DeleteResponse("분석 결과가 삭제되었습니다."));
    }

    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<SecurityReviewResponse> upload(@RequestPart("file") MultipartFile file) {
        return ResponseEntity.ok(securityReviewFacade.reviewUploadedZip(file));
    }

    @PostMapping(value = "/github", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<SecurityReviewResponse> reviewGitHubRepository(@Valid @RequestBody GithubRepositoryReviewRequest request) {
        return ResponseEntity.ok(securityReviewFacade.reviewGitHubRepository(request.repositoryUrl()));
    }
}
