package com.securedeploy.project.progress;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter
public class ComparisonContextConverter implements AttributeConverter<ComparisonContext, String> {
    private static final ObjectMapper MAPPER = new ObjectMapper().registerModule(new JavaTimeModule());
    @Override public String convertToDatabaseColumn(ComparisonContext value) {
        if (value == null) return null;
        try { return MAPPER.writeValueAsString(value); }
        catch (Exception invalid) { throw new IllegalStateException("Cannot encode comparison snapshot"); }
    }
    @Override public ComparisonContext convertToEntityAttribute(String value) {
        if (value == null) return null;
        try {
            var context=MAPPER.readValue(value,ComparisonContext.class);
            if(context.schemaVersion()!=1||context.workspaceScan()!=null&&context.workspaceScan().schemaVersion()!=1)throw new IllegalArgumentException();
            return context;
        }
        catch (Exception invalid) {
            // Keep original stored JSON untouched. Unknown security evidence never becomes COMPLETE/SAFE.
            return new ComparisonContext(0,null,"UNSUPPORTED_SNAPSHOT_REVIEW_REQUIRED",false,java.util.List.of(),null);
        }
    }
}
