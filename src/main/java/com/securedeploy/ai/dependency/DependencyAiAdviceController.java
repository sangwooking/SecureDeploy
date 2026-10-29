package com.securedeploy.ai.dependency;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/api/reviews/{reviewId}/dependencies/ai-proposals")
public class DependencyAiAdviceController {
    private final DependencyAiAdviceService service;
    public DependencyAiAdviceController(DependencyAiAdviceService service){this.service=service;}
    @GetMapping("/provider") public ResponseEntity<?> provider(@PathVariable long reviewId){return json(service.provider(reviewId));}
    @PostMapping public ResponseEntity<?> prepare(@PathVariable long reviewId,@RequestBody DependencyAiAdviceService.Prepare input){return json(service.prepare(reviewId,input));}
    @GetMapping("/{id}") public ResponseEntity<?> get(@PathVariable long reviewId,@PathVariable String id){return json(service.get(reviewId,id));}
    @PostMapping("/{id}/generate") public ResponseEntity<?> generate(@PathVariable long reviewId,@PathVariable String id,@RequestBody DependencyAiAdviceService.Consent input){return json(service.generate(reviewId,id,input));}
    private ResponseEntity<?> json(Object data){return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(data);}
}
