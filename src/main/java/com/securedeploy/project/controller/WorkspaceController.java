package com.securedeploy.project.controller;

import com.securedeploy.project.dto.WorkspaceResponse;
import com.securedeploy.project.service.WorkspaceService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WorkspaceController {
    private final WorkspaceService service;
    public WorkspaceController(WorkspaceService service) { this.service = service; }

    @GetMapping("/api/workspace")
    public WorkspaceResponse workspace() { return service.getWorkspace(); }
}
