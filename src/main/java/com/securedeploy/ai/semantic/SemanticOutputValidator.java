package com.securedeploy.ai.semantic;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.ai.dto.AiConfidence;
import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;
import static com.securedeploy.ai.semantic.SemanticCandidate.*;
import org.springframework.stereotype.Component;

@Component
public class SemanticOutputValidator {
    public static final String PROMPT_VERSION = "semantic-v1";
    private static final Set<CandidateType> ACCESS = Set.of(CandidateType.IDOR, CandidateType.AUTHORIZATION_BYPASS,
            CandidateType.BROKEN_ACCESS_CONTROL, CandidateType.MISSING_AUTHENTICATION);
    private static final Pattern CLAIMS = Pattern.compile("CVE-\\d{4}-\\d+|GHSA-[a-z0-9-]+|(?<![\\w.])\\d+\\.\\d+(?:\\.\\d+)*(?![\\w.])|(?<![\\w])(?:[a-z][a-z0-9_]*\\.){2,}[A-Za-z][A-Za-z0-9_]*|(?<![\\w])/[a-zA-Z][a-zA-Z0-9_/{},.*:-]*");
    private final SemanticSanitizer sanitizer;
    private final SemanticProperties limits;
    public SemanticOutputValidator(SemanticSanitizer sanitizer, SemanticProperties limits) { this.sanitizer = sanitizer; this.limits = limits; }
    private static Map<String, Object> string() { return Map.of("type", "string"); }
    private static Map<String, Object> array(Object item) { return Map.of("type", "array", "items", item); }
    private static Map<String, Object> object(Map<String, Object> properties) {
        return Map.of("type", "object", "additionalProperties", false, "required", List.copyOf(properties.keySet()), "properties", properties);
    }
    public static Map<String, Object> schema(List<SecuritySlice> slices) {
        var evidence = object(Map.of("contextId", string(), "filePath", string(), "startLine", Map.of("type","integer"),
                "endLine", Map.of("type","integer"), "functionName", string(), "evidenceDescription", string()));
        Map<String,Object> p = new LinkedHashMap<>();
        p.put("sliceId", Map.of("type","string","enum",slices.stream().map(SecuritySlice::sliceId).toList()));
        p.put("candidateType", Map.of("type","string","enum",Arrays.stream(CandidateType.values()).map(Enum::name).toList()));
        p.put("title",string()); p.put("semanticAnalysisConfidence",Map.of("type","string","enum",List.of("HIGH","MEDIUM","LOW")));
        p.put("reason",string()); p.put("verificationRequired", Map.of("type","boolean","enum",List.of(true)));
        p.put("evidence",array(evidence)); p.put("verificationSteps",array(string())); p.put("relatedExistingFindingIds",array(string()));
        return object(Map.of("candidates",array(object(p))));
    }
    public static List<Proposal> parse(JsonNode root, ObjectMapper mapper) {
        if (!root.isObject() || root.size()!=1 || !root.path("candidates").isArray() || root.path("candidates").size()>20)
            throw new IllegalArgumentException("Invalid semantic schema");
        List<Proposal> result = new ArrayList<>();
        Set<String> keys = Set.of("sliceId","candidateType","title","semanticAnalysisConfidence","reason","verificationRequired","evidence","verificationSteps","relatedExistingFindingIds");
        for (var node : root.path("candidates")) {
            Set<String> actual = new HashSet<>(); node.fieldNames().forEachRemaining(actual::add);
            if (!actual.equals(keys) || !node.path("verificationRequired").isBoolean() || !node.path("evidence").isArray()
                    || !node.path("verificationSteps").isArray() || !node.path("relatedExistingFindingIds").isArray()) throw new IllegalArgumentException("Invalid semantic schema");
            for (String key : List.of("sliceId","candidateType","title","semanticAnalysisConfidence","reason"))
                if (!node.path(key).isTextual()) throw new IllegalArgumentException("Invalid semantic schema");
            for (var e : node.path("evidence")) {
                Set<String> fields = new HashSet<>(); e.fieldNames().forEachRemaining(fields::add);
                if (!fields.equals(Set.of("contextId","filePath","startLine","endLine","functionName","evidenceDescription"))
                        || !e.path("startLine").isIntegralNumber() || !e.path("endLine").isIntegralNumber()) throw new IllegalArgumentException("Invalid semantic schema");
                for (String key : List.of("contextId","filePath","functionName","evidenceDescription"))
                    if (!e.path(key).isTextual()) throw new IllegalArgumentException("Invalid semantic schema");
            }
            for (String key : List.of("verificationSteps","relatedExistingFindingIds"))
                for (var value : node.path(key)) if (!value.isTextual()) throw new IllegalArgumentException("Invalid semantic schema");
            try { result.add(mapper.treeToValue(node, Proposal.class)); }
            catch (Exception failure) { throw new IllegalArgumentException("Invalid semantic schema"); }
        }
        return List.copyOf(result);
    }
    public record Validated(List<SemanticCandidate> candidates, List<SemanticCandidate> supporting, int rejected, int duplicates) { }
    public Validated validate(List<Proposal> proposals, List<SecuritySlice> slices, String model) {
        if (proposals==null || proposals.size()>limits.getMaxCandidates()) throw new IllegalArgumentException("Semantic candidate budget exceeded");
        List<SemanticCandidate> candidates = new ArrayList<>(), supporting = new ArrayList<>();
        Set<String> seen = new HashSet<>(); int rejected = 0, duplicates = 0;
        for (var p : proposals) {
            try {
                var slice = slices.stream().filter(s -> s.sliceId().equals(p.sliceId())).findFirst().orElseThrow();
                if (p.candidateType()==null || p.semanticAnalysisConfidence()==null || !p.verificationRequired()
                        || !text(p.title(),200) || !text(p.reason(),1600) || p.evidence()==null || p.evidence().isEmpty()
                        || p.evidence().size()>6 || p.verificationSteps()==null || p.verificationSteps().isEmpty()
                        || p.verificationSteps().size()>8 || p.verificationSteps().stream().anyMatch(s -> !text(s,500))
                        || p.relatedExistingFindingIds()==null || p.relatedExistingFindingIds().size()>20) throw new IllegalArgumentException();
                List<SecuritySlice.CodeContext> cited = new ArrayList<>();
                for (var e : p.evidence()) {
                    var c = slice.contexts().stream().filter(x -> x.contextId().equals(e.contextId())).findFirst().orElseThrow();
                    if (!c.filePath().equals(e.filePath()) || !c.functionName().equals(e.functionName())
                            || e.startLine()<c.startLine() || e.endLine()>c.endLine() || e.endLine()<e.startLine()
                            || !text(e.evidenceDescription(),800)) throw new IllegalArgumentException();
                    cited.add(c);
                }
                if (p.relatedExistingFindingIds().stream().anyMatch(id -> slice.existingFindings().stream().noneMatch(f -> f.findingId().equals(id)))) throw new IllegalArgumentException();
                // Mechanical grounding, not proof that the model's security interpretation is true.
                String input = slice.toString();
                String prose = p.title()+" "+p.reason()+" "+p.verificationSteps()+" "+p.evidence().stream().map(Evidence::evidenceDescription).toList();
                var claims = CLAIMS.matcher(prose);
                while (claims.find()) if (!input.contains(claims.group())) throw new IllegalArgumentException();
                var primary = p.evidence().get(0);
                String identity = p.candidateType()+"|"+primary.filePath()+"|"+primary.functionName()+"|"+slice.endpoint()+"|"+primary.startLine()+":"+primary.endLine();
                if (!seen.add(identity)) { duplicates++; continue; }
                // Only same-family findings in the cited method are counted as supporting evidence.
                var related = slice.existingFindings().stream().filter(f -> sameRisk(p.candidateType(), f.ruleId())
                        && cited.stream().anyMatch(c -> c.filePath().equals(f.filePath()) && f.line()>=c.startLine() && f.line()<=c.endLine()))
                        .map(SecuritySlice.ExistingFinding::findingId).distinct().sorted().toList();
                boolean authPresent = ACCESS.contains(p.candidateType()) && slice.contexts().stream().anyMatch(SecuritySlice.CodeContext::authorizationDeclared);
                var steps = new ArrayList<>(p.verificationSteps().stream().map(s -> sanitizer.text(s,500)).toList());
                if (ACCESS.contains(p.candidateType())) steps.add("공통 filter/interceptor, Service 권한 검사 및 소유자 조건을 확인하세요. 현재 Slice만으로 누락을 확정할 수 없습니다.");
                var candidate = new SemanticCandidate(SecuritySliceCollector.id(identity), p.sliceId(), p.candidateType(), sanitizer.text(p.title(),200),
                        authPresent ? AiConfidence.LOW : p.semanticAnalysisConfidence(), sanitizer.text(p.reason(),1600), true,
                        p.evidence().stream().map(e -> new Evidence(e.contextId(),e.filePath(),e.startLine(),e.endLine(),e.functionName(),sanitizer.text(e.evidenceDescription(),800))).toList(),
                        List.copyOf(steps), related, Instant.now(), "openai", model, PROMPT_VERSION);
                if (related.isEmpty()) candidates.add(candidate); else supporting.add(candidate);
            } catch (RuntimeException invalid) { rejected++; }
        }
        return new Validated(List.copyOf(candidates), List.copyOf(supporting), rejected, duplicates);
    }
    private static boolean text(String value,int max) { return value!=null && !value.isBlank() && value.length()<=max; }
    private static boolean sameRisk(CandidateType type, String rule) {
        return (type==CandidateType.MISSING_AUTHENTICATION && "PERMIT_ALL_USAGE".equals(rule))
                || (type==CandidateType.SENSITIVE_DATA_EXPOSURE && Set.of("HARDCODED_SECRET","HARDCODED_PASSWORD","HARDCODED_FRONTEND_SECRET").contains(rule));
    }
}
