package com.securedeploy.ai.remediation;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter
public class RemediationSnapshotConverter implements AttributeConverter<RemediationSnapshot, String> {
    private static final ObjectMapper MAPPER = new ObjectMapper().registerModule(new JavaTimeModule());
    @Override public String convertToDatabaseColumn(RemediationSnapshot snapshot) {
        if (snapshot == null) return null;
        try { return MAPPER.writeValueAsString(snapshot); }
        catch (Exception exception) { throw new IllegalStateException("Cannot encode remediation snapshot"); }
    }
    @Override public RemediationSnapshot convertToEntityAttribute(String json) {
        if (json == null) return null;
        try { return MAPPER.readValue(json, RemediationSnapshot.class); }
        catch (Exception exception) { throw new IllegalStateException("Cannot decode remediation snapshot"); }
    }
}
