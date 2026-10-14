package com.securedeploy.upload.controller;

import com.securedeploy.upload.service.UploadPolicy;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UploadPolicyController {
    private final UploadPolicy policy;

    public UploadPolicyController(UploadPolicy policy) { this.policy = policy; }

    @GetMapping("/api/reviews/upload-policy")
    public UploadPolicy.PolicyResponse getPolicy() { return policy.response(); }
}
