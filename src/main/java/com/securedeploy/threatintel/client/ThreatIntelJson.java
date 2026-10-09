package com.securedeploy.threatintel.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import org.springframework.web.client.RestClient;

final class ThreatIntelJson {
    private ThreatIntelJson() { }
    static JsonNode get(RestClient http, ObjectMapper mapper, URI uri, int maxBytes) {
        return http.get().uri(uri).exchange((request, response) -> {
            if (!response.getStatusCode().is2xxSuccessful()) throw new IllegalStateException("Threat source unavailable");
            byte[] data = response.getBody().readNBytes(maxBytes + 1);
            if (data.length > maxBytes) throw new IllegalStateException("Threat source size limit");
            JsonNode root = mapper.readTree(data);
            if (root == null || !root.isObject()) throw new IllegalStateException("Invalid threat JSON");
            return root;
        });
    }
    static String text(JsonNode node, String name, int limit, boolean required) {
        JsonNode value = node.get(name);
        if (value == null || value.isNull()) {
            if (required) throw new IllegalStateException("Missing threat field");
            return null;
        }
        if (!value.isTextual() || value.textValue().length() > limit || (required && value.textValue().isBlank())) {
            throw new IllegalStateException("Invalid threat field");
        }
        return value.textValue();
    }
}
