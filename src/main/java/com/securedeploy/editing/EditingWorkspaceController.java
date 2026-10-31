package com.securedeploy.editing;

import java.io.IOException;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/editing-workspaces")
public class EditingWorkspaceController {
    private final EditingWorkspaceService service;
    public EditingWorkspaceController(EditingWorkspaceService service) { this.service = service; }
    @PostMapping(value = "/zip/{reviewId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> zip(@PathVariable long reviewId, @RequestPart MultipartFile file,@RequestParam(defaultValue="false") boolean sourceRetentionAcknowledged) throws IOException { service.requireSourceConsent(reviewId,sourceRetentionAcknowledged);return json(service.create(reviewId, file)); }
    @PostMapping("/github/{reviewId}")
    public ResponseEntity<?> github(@PathVariable long reviewId,@RequestParam(defaultValue="false") boolean sourceRetentionAcknowledged) throws IOException { service.requireSourceConsent(reviewId,sourceRetentionAcknowledged);return json(service.create(reviewId, null)); }
    @GetMapping("/review/{reviewId}/source")
    public ResponseEntity<?> source(@PathVariable long reviewId){return json(service.sourceVerification(reviewId));}
    @ExceptionHandler(SourceVerificationException.class)
    public ResponseEntity<?> sourceMismatch(SourceVerificationException error){return ResponseEntity.status(error.getStatus()).cacheControl(CacheControl.noStore()).body(java.util.Map.of("code","SOURCE_"+error.verification.status(),"message",error.getMessage(),"sourceVerification",error.verification));}
    @GetMapping("/review/{reviewId}/active")
    public ResponseEntity<?> active(@PathVariable long reviewId) { return json(service.discover(reviewId)); }
    @ExceptionHandler(EditingConflictException.class)
    public ResponseEntity<?> conflict(EditingConflictException error) {
        return ResponseEntity.status(409).cacheControl(CacheControl.noStore()).body(java.util.Map.of("code",error.code,"message",error.getMessage()));
    }
    @GetMapping("/{id}")
    public ResponseEntity<?> get(@PathVariable String id) { return json(service.get(id)); }
    @GetMapping("/{id}/files/{fileId}")
    public ResponseEntity<?> file(@PathVariable String id, @PathVariable String fileId) { return json(service.content(id, fileId)); }
    @PutMapping("/{id}/files/{fileId}")
    public ResponseEntity<?> save(@PathVariable String id, @PathVariable String fileId, @RequestBody EditingWorkspaceService.Change request) { return json(service.save(id, fileId, request, false)); }
    @PostMapping("/{id}/files/{fileId}/revert")
    public ResponseEntity<?> revert(@PathVariable String id, @PathVariable String fileId, @RequestBody EditingWorkspaceService.Change request) { return json(service.save(id, fileId, request, true)); }
    @GetMapping("/{id}/files/{fileId}/diff")
    public ResponseEntity<?> diff(@PathVariable String id, @PathVariable String fileId) throws IOException { return json(service.diff(id, fileId)); }
    @PostMapping("/{id}/export/{format}")
    public ResponseEntity<byte[]> export(@PathVariable String id, @PathVariable String format, @RequestBody EditingWorkspaceService.Approval request) throws IOException {
        var download = service.download(id, format, request);
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).header("X-Content-Type-Options", "nosniff")
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment().filename(download.filename()).build().toString())
                .header("X-SecureDeploy-Provenance-SHA256",download.provenanceHash()).header("X-SecureDeploy-Revision",Long.toString(download.revision())).header("X-SecureDeploy-Export-Approved","true")
                .contentType(MediaType.parseMediaType(download.type())).body(download.bytes());
    }
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable String id) { service.delete(id); return json(java.util.Map.of("deleted", true)); }
    private ResponseEntity<?> json(Object value) { return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(value); }
}
