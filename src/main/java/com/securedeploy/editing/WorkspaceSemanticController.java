package com.securedeploy.editing;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/api/editing-workspaces/{workspace}/semantic-review")
public class WorkspaceSemanticController {
 private final WorkspaceSemanticService service;
 public WorkspaceSemanticController(WorkspaceSemanticService service){this.service=service;}
 @PostMapping public ResponseEntity<?> prepare(@PathVariable String workspace,@RequestBody WorkspaceSemanticService.Request request){return json(service.prepare(workspace,request));}
 @GetMapping("/{id}") public ResponseEntity<?> get(@PathVariable String workspace,@PathVariable String id){return json(service.get(workspace,id));}
 @PostMapping("/{id}/generate") public ResponseEntity<?> generate(@PathVariable String workspace,@PathVariable String id,@RequestBody WorkspaceSemanticService.Consent request){return json(service.generate(workspace,id,request));}
 private ResponseEntity<?> json(Object value){return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(value);}
}
