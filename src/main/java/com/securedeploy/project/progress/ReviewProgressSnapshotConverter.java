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
        try { return MAPPER.readValue(value, ReviewProgressSnapshot.class); }
        catch (Exception invalid) { throw new IllegalStateException("Cannot decode comparison snapshot"); }
    }
}
