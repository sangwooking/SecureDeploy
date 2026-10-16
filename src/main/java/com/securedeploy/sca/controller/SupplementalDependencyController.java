package com.securedeploy.sca.controller;

import com.securedeploy.sca.dto.*;
import com.securedeploy.sca.service.SupplementalDependencyService;
import jakarta.validation.Valid;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/reviews/{reviewId}/dependencies")
public class SupplementalDependencyController {
    private final SupplementalDependencyService service;
    public SupplementalDependencyController(SupplementalDependencyService service) { this.service = service; }

    @PostMapping("/supplemental-lookup")
    public ResponseEntity<SupplementalDependencyResponse> lookup(@PathVariable Long reviewId,
            @Valid @RequestBody SupplementalDependencyRequest request) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(service.lookup(reviewId, request));
    }
}
