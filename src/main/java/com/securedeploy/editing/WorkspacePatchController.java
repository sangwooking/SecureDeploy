package com.securedeploy.editing;

import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/editing-workspaces")
public class WorkspacePatchController {
    private final WorkspacePatchService patches;
    private final EditingWorkspaceService workspaces;
    public WorkspacePatchController(WorkspacePatchService patches,EditingWorkspaceService workspaces){this.patches=patches;this.workspaces=workspaces;}
    @GetMapping("/patch-provider") public ResponseEntity<?> provider(){return json(patches.provider());}
    @PostMapping("/{id}/patches") public ResponseEntity<?> prepare(@PathVariable String id,@RequestBody WorkspacePatch.Prepare request){return json(patches.prepare(id,request));}
    @GetMapping("/{id}/patches") public ResponseEntity<?> list(@PathVariable String id){return json(workspaces.patches(id));}
    @GetMapping("/{id}/patches/{proposal}") public ResponseEntity<?> get(@PathVariable String id,@PathVariable String proposal){return json(workspaces.patch(id,proposal));}
    @PostMapping("/{id}/patches/{proposal}/generate") public ResponseEntity<?> generate(@PathVariable String id,@PathVariable String proposal,@RequestBody WorkspacePatch.Consent request){return json(patches.generate(id,proposal,request));}
    @PostMapping("/{id}/patches/{proposal}/reject") public ResponseEntity<?> reject(@PathVariable String id,@PathVariable String proposal){return json(patches.reject(id,proposal));}
    @PostMapping("/{id}/patches/{proposal}/apply") public ResponseEntity<?> apply(@PathVariable String id,@PathVariable String proposal,@RequestBody WorkspacePatch.Decision request){return json(workspaces.applyPatch(id,proposal,request));}
    private ResponseEntity<?> json(Object body){return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(body);}
}
