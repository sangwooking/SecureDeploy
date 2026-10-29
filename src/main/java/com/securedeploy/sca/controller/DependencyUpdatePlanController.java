package com.securedeploy.sca.controller;
import com.securedeploy.sca.service.DependencyUpdatePlanService;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/api/reviews/{reviewId}/dependencies")
public class DependencyUpdatePlanController {
    private final DependencyUpdatePlanService service;
    public DependencyUpdatePlanController(DependencyUpdatePlanService service){this.service=service;}
    @GetMapping("/update-plans")
    public ResponseEntity<DependencyUpdatePlanService.Snapshot> get(@PathVariable long reviewId){
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(service.get(reviewId));
    }
}
