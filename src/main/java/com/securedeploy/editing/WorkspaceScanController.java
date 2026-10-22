package com.securedeploy.editing;

import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/editing-workspaces")
public class WorkspaceScanController {
    private final WorkspaceScanService scans;
    public WorkspaceScanController(WorkspaceScanService scans) { this.scans = scans; }
    @PostMapping("/{id}/scans")
    public ResponseEntity<WorkspaceScanService.View> start(@PathVariable String id, @RequestBody WorkspaceScanService.Request request) {
        return ResponseEntity.accepted().cacheControl(CacheControl.noStore()).body(scans.start(id, request));
    }
    @GetMapping("/scans/{scanId}")
    public ResponseEntity<WorkspaceScanService.View> get(@PathVariable String scanId) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(scans.get(scanId));
    }
}
