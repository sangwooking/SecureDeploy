package com.securedeploy.report.service;

import com.lowagie.text.Document;
import com.lowagie.text.DocumentException;
import com.lowagie.text.Element;
import com.lowagie.text.Font;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;
import com.lowagie.text.pdf.BaseFont;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import com.securedeploy.auth.service.ReviewAccessService;
import com.securedeploy.ai.dto.AiReviewResponse;
import com.securedeploy.ai.dto.AiReviewResultResponse;
import com.securedeploy.ai.service.AiReviewService;
import com.securedeploy.global.error.SecureDeployException;
import com.securedeploy.persistence.entity.ReviewEntity;
import com.securedeploy.persistence.entity.VulnerabilityEntity;
import com.securedeploy.persistence.repository.ReviewRepository;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.format.DateTimeFormatter;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class PdfReportService {

    private static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final String[] FONT_CANDIDATES = {
            "/System/Library/Fonts/AppleSDGothicNeo.ttc,0",
            "/Library/Fonts/AppleGothic.ttf",
            "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
            "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc,0",
            "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc,0"
    };

    private final ReviewRepository reviewRepository;
    private final ReviewAccessService reviewAccessService;
    private final AiReviewService aiReviewService;

    public PdfReportService(ReviewRepository reviewRepository, ReviewAccessService reviewAccessService, AiReviewService aiReviewService) {
        this.reviewRepository = reviewRepository;
        this.reviewAccessService = reviewAccessService;
        this.aiReviewService = aiReviewService;
    }

    @Transactional(readOnly = true)
    public byte[] generate(Long reviewId) {
        ReviewEntity review = findReview(reviewId);
        return generatePdf(review, null);
    }

    @Transactional(readOnly = true)
    public byte[] generateWithAiReview(Long reviewId) {
        ReviewEntity review = findReview(reviewId);
        AiReviewResultResponse aiReview = aiReviewService.generateReview(reviewId);
        return generatePdf(review, aiReview);
    }

    private ReviewEntity findReview(Long reviewId) {
        return reviewAccessService.findAccessibleReviewWithVulnerabilities(reviewId, "PDF 리포트를 생성할 분석 이력을 찾을 수 없습니다.");
    }

    private byte[] generatePdf(ReviewEntity review, AiReviewResultResponse aiReview) {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            Document document = new Document(PageSize.A4, 36, 36, 42, 42);
            PdfWriter.getInstance(document, outputStream);
            document.open();

            ReportFonts fonts = createFonts();
            addTitle(document, fonts);
            addSummary(document, review, fonts);
            addVulnerabilities(document, review.getVulnerabilities(), fonts);
            if (aiReview != null) {
                addAiReviews(document, aiReview.reviews(), fonts);
            }

            document.close();
            return outputStream.toByteArray();
        } catch (DocumentException | IOException exception) {
            throw new SecureDeployException(HttpStatus.INTERNAL_SERVER_ERROR, "PDF 리포트 생성 중 오류가 발생했습니다.");
        }
    }

    private void addTitle(Document document, ReportFonts fonts) throws DocumentException {
        Paragraph title = new Paragraph("SecureDeploy Security Review Report", fonts.title());
        title.setAlignment(Element.ALIGN_CENTER);
        title.setSpacingAfter(18);
        document.add(title);
    }

    private void addSummary(Document document, ReviewEntity review, ReportFonts fonts) throws DocumentException {
        document.add(sectionTitle("Review Summary", fonts));

        PdfPTable table = new PdfPTable(new float[]{1.2f, 2.8f});
        table.setWidthPercentage(100);
        addRow(table, "Project Name", review.getProjectName(), fonts);
        addRow(table, "Source Type", review.getSourceType().name(), fonts);
        if (review.getRepositoryUrl() != null && !review.getRepositoryUrl().isBlank()) {
            addRow(table, "GitHub URL", review.getRepositoryUrl(), fonts);
        }
        addRow(table, "Reviewed At", review.getCreatedAt().format(DATE_TIME_FORMATTER), fonts);
        addRow(table, "Scanned Files", String.valueOf(review.getScannedFileCount()), fonts);
        addRow(table, "Vulnerabilities", String.valueOf(review.getVulnerabilityCount()), fonts);
        addRow(table, "Security Score", review.getSecurityScore() + " / 100", fonts);
        addRow(table, "Deployment Status", review.getDeploymentStatus(), fonts);
        document.add(table);
        document.add(spacer(12));
    }

    private void addVulnerabilities(Document document, List<VulnerabilityEntity> vulnerabilities, ReportFonts fonts) throws DocumentException {
        document.add(sectionTitle("Vulnerability Details", fonts));

        if (vulnerabilities.isEmpty()) {
            Paragraph empty = new Paragraph("No vulnerabilities were detected.", fonts.body());
            empty.setSpacingAfter(8);
            document.add(empty);
            return;
        }

        int index = 1;
        for (VulnerabilityEntity vulnerability : vulnerabilities) {
            Paragraph heading = new Paragraph(index + ". " + vulnerability.getRuleId(), fonts.subtitle());
            heading.setSpacingBefore(8);
            heading.setSpacingAfter(6);
            document.add(heading);

            PdfPTable table = new PdfPTable(new float[]{1.2f, 3.8f});
            table.setWidthPercentage(100);
            addRow(table, "Severity", vulnerability.getSeverity().name(), fonts);
            addRow(table, "Category", vulnerability.getCategory().name(), fonts);
            addRow(table, "File Path", vulnerability.getFilePath(), fonts);
            addRow(table, "Line", String.valueOf(vulnerability.getLine()), fonts);
            addRow(table, "Message", vulnerability.getMessage(), fonts);
            addRow(table, "Recommendation", vulnerability.getRecommendation(), fonts);
            addRow(table, "Evidence", nullToDash(vulnerability.getEvidence()), fonts);
            document.add(table);
            index++;
        }
        document.add(spacer(12));
    }

    private void addAiReviews(Document document, List<AiReviewResponse> reviews, ReportFonts fonts) throws DocumentException {
        document.add(sectionTitle("AI Security Review", fonts));

        if (reviews.isEmpty()) {
            document.add(new Paragraph("No AI review items were generated.", fonts.body()));
            return;
        }

        int index = 1;
        for (AiReviewResponse review : reviews) {
            Paragraph heading = new Paragraph(index + ". " + review.ruleId() + " - " + review.title(), fonts.subtitle());
            heading.setSpacingBefore(8);
            heading.setSpacingAfter(6);
            document.add(heading);

            PdfPTable table = new PdfPTable(new float[]{1.2f, 3.8f});
            table.setWidthPercentage(100);
            addRow(table, "Priority", review.priority(), fonts);
            addRow(table, "Description", review.description(), fonts);
            addRow(table, "Risk", review.riskExplanation(), fonts);
            addRow(table, "Attack Scenario", review.attackScenario(), fonts);
            addRow(table, "Recommendation", review.recommendation(), fonts);
            document.add(table);
            index++;
        }
    }

    private Paragraph sectionTitle(String text, ReportFonts fonts) {
        Paragraph paragraph = new Paragraph(text, fonts.section());
        paragraph.setSpacingBefore(8);
        paragraph.setSpacingAfter(8);
        return paragraph;
    }

    private Paragraph spacer(float height) {
        Paragraph paragraph = new Paragraph(" ");
        paragraph.setSpacingAfter(height);
        return paragraph;
    }

    private void addRow(PdfPTable table, String label, String value, ReportFonts fonts) {
        PdfPCell labelCell = new PdfPCell(new Phrase(label, fonts.label()));
        labelCell.setPadding(7);
        labelCell.setBackgroundColor(new java.awt.Color(240, 244, 248));
        table.addCell(labelCell);

        PdfPCell valueCell = new PdfPCell(new Phrase(nullToDash(value), fonts.body()));
        valueCell.setPadding(7);
        table.addCell(valueCell);
    }

    private String nullToDash(String value) {
        return value == null || value.isBlank() ? "-" : value;
    }

    private ReportFonts createFonts() throws IOException, DocumentException {
        BaseFont baseFont = createBaseFont();
        return new ReportFonts(
                new Font(baseFont, 18, Font.BOLD),
                new Font(baseFont, 13, Font.BOLD),
                new Font(baseFont, 11, Font.BOLD),
                new Font(baseFont, 9, Font.BOLD),
                new Font(baseFont, 9, Font.NORMAL)
        );
    }

    private BaseFont createBaseFont() throws IOException, DocumentException {
        for (String candidate : FONT_CANDIDATES) {
            String path = candidate.contains(",") ? candidate.substring(0, candidate.indexOf(',')) : candidate;
            if (Files.exists(Path.of(path))) {
                return BaseFont.createFont(candidate, BaseFont.IDENTITY_H, BaseFont.EMBEDDED);
            }
        }
        return BaseFont.createFont(BaseFont.HELVETICA, BaseFont.WINANSI, BaseFont.NOT_EMBEDDED);
    }

    private record ReportFonts(Font title, Font section, Font subtitle, Font label, Font body) {
    }
}
