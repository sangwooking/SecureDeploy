package com.securedeploy.project.progress;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter
public class ReviewProgressSnapshotConverter implements AttributeConverter<ReviewProgressSnapshot, String> {
    private static final ObjectMapper MAPPER = new ObjectMapper().registerModule(new JavaTimeModule());
    @Override public String convertToDatabaseColumn(ReviewProgressSnapshot value) {
        if (value == null) return null;
        try { return MAPPER.writeValueAsString(value); }
        catch (Exception invalid) { throw new IllegalStateException("Cannot encode comparison snapshot"); }
    }
    @Override public ReviewProgressSnapshot convertToEntityAttribute(String value) {
        if (value == null) return null;
        try {
            var snapshot=MAPPER.readValue(value,ReviewProgressSnapshot.class);
            if(snapshot.comparisonSchemaVersion()!=1)throw new IllegalArgumentException();
            return snapshot;
        }
        catch (Exception invalid) {
            return new ReviewProgressSnapshot(0,null,null,null,null,null,java.time.Instant.EPOCH,
                ReviewProgressSnapshot.Status.UNAVAILABLE,"지원하지 않는 비교 근거입니다. 원본 위험 결과를 확인해 주세요.",
                null,null,java.util.Map.of(),java.util.List.of(),java.util.List.of(),
                java.util.List.of("UNSUPPORTED_SNAPSHOT_REVIEW_REQUIRED; original stored evidence retained"),null,null,null);
        }
    }
}
