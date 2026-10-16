package com.securedeploy.sca.parser;

import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.project.model.ProjectFile;
import java.util.*;

final class JsonSourceLines {
    private JsonSourceLines() { }
    static Map<String, Integer> read(ObjectMapper mapper, ProjectFile file) throws Exception {
        Map<String, Integer> result = new HashMap<>();
        try (var parser = mapper.createParser(String.join("\n", file.lines()))) {
            while (parser.nextToken() != null) {
                if (parser.currentToken() == JsonToken.FIELD_NAME) {
                    result.put(parser.getParsingContext().pathAsPointer().toString(), parser.currentTokenLocation().getLineNr());
                }
            }
        }
        return result;
    }
    static String key(String value) { return value.replace("~", "~0").replace("/", "~1"); }
}
