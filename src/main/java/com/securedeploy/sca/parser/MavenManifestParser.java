package com.securedeploy.sca.parser;
import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.sca.model.*;
import java.io.StringReader;
import java.util.*;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.*;
import org.xml.sax.InputSource;
import org.xml.sax.helpers.DefaultHandler;

public class MavenManifestParser {
    public List<DependencyComponent> parse(ProjectFile file) throws Exception {
        var factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        var builder = factory.newDocumentBuilder();
        builder.setErrorHandler(new DefaultHandler());
        Element root = builder.parse(new InputSource(new StringReader(String.join("\n", file.lines())))).getDocumentElement();
        if (!"project".equals(root.getLocalName())) throw new IllegalArgumentException("Not a Maven project");
        Map<String, String> properties = new HashMap<>();
        for (Element property : children(child(root, "properties"))) {
            properties.put(property.getLocalName(), property.getTextContent().strip());
        }
        for (String key : List.of("groupId", "artifactId", "version")) {
            String value = text(root, key);
            if (value != null) properties.put("project." + key, value);
        }
        List<DependencyComponent> result = new ArrayList<>();
        for (Element dependency : children(child(root, "dependencies"))) {
            if (!"dependency".equals(dependency.getLocalName())) continue;
            String group = resolve(text(dependency, "groupId"), properties);
            String artifact = resolve(text(dependency, "artifactId"), properties);
            result.add(VersionClassifier.component(ScaEcosystem.MAVEN, group == null || artifact == null ? null : group + ":" + artifact,
                    resolve(text(dependency, "version"), properties),
                    Optional.ofNullable(text(dependency, "scope")).orElse("compile"), true, file.relativePath(), 0));
        }
        return result;
    }
    private String resolve(String value, Map<String, String> properties) {
        if (value == null) return null;
        for (int pass = 0; pass < 10 && value.contains("$" + "{"); pass++) {
            String previous = value;
            for (var entry : properties.entrySet()) {
                value = value.replace("$" + "{" + entry.getKey() + "}", entry.getValue());
                if (value.length() > 256) return "<unresolved-property>";
            }
            if (value.equals(previous)) break;
        }
        return value;
    }
    private static List<Element> children(Element parent) {
        List<Element> result = new ArrayList<>();
        if (parent != null) for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element e) result.add(e);
        }
        return result;
    }
    private static Element child(Element parent, String name) {
        return children(parent).stream().filter(e -> name.equals(e.getLocalName())).findFirst().orElse(null);
    }
    private static String text(Element parent, String name) {
        Element value = child(parent, name);
        return value == null ? null : value.getTextContent().strip();
    }
}
