package com.securedeploy.analysis.typescript;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter
public class ServerAnalysisConverter implements AttributeConverter<ServerAnalysisSnapshot, String> {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    public String convertToDatabaseColumn(ServerAnalysisSnapshot value) {
        if (value == null) return null;
        try { return MAPPER.writeValueAsString(value); }
        catch (Exception failure) { throw new IllegalStateException("Cannot encode server analysis"); }
    }
    public ServerAnalysisSnapshot convertToEntityAttribute(String value) {
        if (value == null) return null;
        try { return MAPPER.readValue(value, ServerAnalysisSnapshot.class); }
        catch (Exception failure) { throw new IllegalStateException("Cannot decode server analysis"); }
    }
}
