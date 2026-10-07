package com.securedeploy.risk.persistence;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.securedeploy.risk.model.RiskAssessment;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter
public class RiskAssessmentConverter implements AttributeConverter<RiskAssessment, String> {
    private static final ObjectMapper MAPPER = new ObjectMapper().registerModule(new JavaTimeModule());
    @Override public String convertToDatabaseColumn(RiskAssessment assessment) {
        if (assessment == null) return null;
        try { return MAPPER.writeValueAsString(assessment); }
        catch (Exception exception) { throw new IllegalStateException("Cannot encode risk assessment"); }
    }
    @Override public RiskAssessment convertToEntityAttribute(String json) {
        if (json == null) return null;
        try { return MAPPER.readValue(json, RiskAssessment.class); }
        catch (Exception exception) { throw new IllegalStateException("Cannot decode risk assessment"); }
    }
}
