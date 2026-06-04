package com.securedeploy.report.controller;

import com.securedeploy.report.service.PdfReportService;
import com.securedeploy.report.service.ReportFileNameGenerator;
import java.nio.charset.StandardCharsets;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/reviews")
public class ReportController {

    private final PdfReportService pdfReportService;
    private final ReportFileNameGenerator fileNameGenerator;

    public ReportController(PdfReportService pdfReportService, ReportFileNameGenerator fileNameGenerator) {
        this.pdfReportService = pdfReportService;
        this.fileNameGenerator = fileNameGenerator;
    }

    @GetMapping(value = "/{reviewId}/report", produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<byte[]> downloadReport(@PathVariable Long reviewId) {
        return pdfResponse(pdfReportService.generate(reviewId), fileNameGenerator.generate(reviewId));
    }

    @GetMapping(value = "/{reviewId}/report/ai", produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<byte[]> downloadAiReport(@PathVariable Long reviewId) {
        return pdfResponse(pdfReportService.generateWithAiReview(reviewId), fileNameGenerator.generateAi(reviewId));
    }

    private ResponseEntity<byte[]> pdfResponse(byte[] report, String fileName) {
        ContentDisposition contentDisposition = ContentDisposition.attachment()
                .filename(fileName, StandardCharsets.UTF_8)
                .build();

        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_PDF)
                .header(HttpHeaders.CONTENT_DISPOSITION, contentDisposition.toString())
                .body(report);
    }
}
