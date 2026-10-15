package com.securedeploy.github.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter
public class GitHubSourceSnapshotConverter implements AttributeConverter<GitHubSourceSnapshot, String> {
    private static final ObjectMapper MAPPER = new ObjectMapper().registerModule(new JavaTimeModule());
    public String convertToDatabaseColumn(GitHubSourceSnapshot value) {
        if (value == null) return null;
        try { return MAPPER.writeValueAsString(value); }
        catch (Exception invalid) { throw new IllegalStateException("Cannot encode GitHub source metadata"); }
    }
    public GitHubSourceSnapshot convertToEntityAttribute(String value) {
        if (value == null) return null;
        try { return MAPPER.readValue(value, GitHubSourceSnapshot.class); }
        catch (Exception invalid) { throw new IllegalStateException("Cannot decode GitHub source metadata"); }
    }
}
