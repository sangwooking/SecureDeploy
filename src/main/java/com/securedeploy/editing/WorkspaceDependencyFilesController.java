package com.securedeploy.editing;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/api/editing-workspaces/{workspace}/dependency-files")
public class WorkspaceDependencyFilesController {
 private final WorkspaceDependencyFilesService service;
 public WorkspaceDependencyFilesController(WorkspaceDependencyFilesService service){this.service=service;}
 @PostMapping public ResponseEntity<?> prepare(@PathVariable String workspace,@RequestBody WorkspaceDependencyFilesService.Prepare request){return json(service.prepare(workspace,request));}
 @GetMapping("/{id}") public ResponseEntity<?> get(@PathVariable String workspace,@PathVariable String id){return json(service.get(workspace,id));}
 @PostMapping("/{id}/generate") public ResponseEntity<?> generate(@PathVariable String workspace,@PathVariable String id,@RequestBody WorkspaceDependencyFilesService.Consent request){return json(service.generate(workspace,id,request));}
 @PostMapping("/{id}/apply") public ResponseEntity<?> apply(@PathVariable String workspace,@PathVariable String id,@RequestBody WorkspaceDependencyFilesService.Consent request){return json(service.apply(workspace,id,request));}
 private ResponseEntity<?> json(Object v){return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(v);}
}
