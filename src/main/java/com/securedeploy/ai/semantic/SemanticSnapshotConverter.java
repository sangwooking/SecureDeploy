package com.securedeploy.ai.semantic;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.persistence.*;

@Converter
public class SemanticSnapshotConverter implements AttributeConverter<SemanticSnapshot,String> {
    private static final ObjectMapper MAPPER = new ObjectMapper().registerModule(new JavaTimeModule());
    @Override public String convertToDatabaseColumn(SemanticSnapshot value) {
        if (value==null) return null;
        try { return MAPPER.writeValueAsString(value); }
        catch (Exception invalid) { throw new IllegalStateException("Cannot encode semantic snapshot"); }
    }
    @Override public SemanticSnapshot convertToEntityAttribute(String value) {
        if (value==null) return null;
        try { return MAPPER.readValue(value,SemanticSnapshot.class); }
        catch (Exception invalid) { throw new IllegalStateException("Cannot decode semantic snapshot"); }
    }
}
