package com.securedeploy.project.coverage;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter
public class CoverageLedgerConverter implements AttributeConverter<CoverageLedger, String> {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    public String convertToDatabaseColumn(CoverageLedger value) {
        if (value == null) return null;
        try { return MAPPER.writeValueAsString(value); }
        catch (Exception failure) { throw new IllegalStateException("Cannot encode coverage ledger"); }
    }
    public CoverageLedger convertToEntityAttribute(String value) {
        if (value == null) return null;
        try { return MAPPER.readValue(value, CoverageLedger.class); }
        catch (Exception failure) { throw new IllegalStateException("Cannot decode coverage ledger"); }
    }
}
