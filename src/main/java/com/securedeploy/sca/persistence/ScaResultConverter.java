package com.securedeploy.sca.persistence;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.securedeploy.sca.model.ScaResult;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter
public class ScaResultConverter implements AttributeConverter<ScaResult, String> {
    private static final ObjectMapper MAPPER = new ObjectMapper().registerModule(new JavaTimeModule());
    @Override
    public String convertToDatabaseColumn(ScaResult result) {
        if (result == null) return null;
        try { return MAPPER.writeValueAsString(result); }
        catch (Exception exception) { throw new IllegalStateException("Cannot encode SCA result"); }
    }
    @Override
    public ScaResult convertToEntityAttribute(String json) {
        if (json == null) return null;
        try { return MAPPER.readValue(json, ScaResult.class); }
        catch (Exception exception) { throw new IllegalStateException("Cannot decode SCA result"); }
    }
}
