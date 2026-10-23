package com.securedeploy.editing;

import com.securedeploy.ai.remediation.RemediationSanitizer;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

/** Closed properties and statically verified response-object patch contracts. */
public final class WorkspacePatch {
    private WorkspacePatch() { }
    public record Provider(String name, String model, boolean available) { }
    static final Provider DETERMINISTIC = new Provider("DETERMINISTIC", "AST_FIELD_REMOVAL_V1", true);
    public record FixOption(String method, String reason) { }
    public record Prepare(String fileId, long findingId, long revision, String originalHash, String currentHash,String flowFindingId) {
        public Prepare(String fileId,long findingId,long revision,String originalHash,String currentHash){this(fileId,findingId,revision,originalHash,currentHash,null);}
    }
    public record Consent(long revision, String currentHash, boolean consented) { }
    public record Decision(long revision, String currentHash, boolean approved,boolean responseContractAcknowledged) {
        public Decision(long revision,String currentHash,boolean approved){this(revision,currentHash,approved,false);}
    }
    public record Prompt(String instructions, String untrustedData, Map<String,Object> schema) { }
    public record Output(String decision, String fileId, int startLine, String expectedHash, String replacement,
                         String explanation, List<String> verificationSteps, List<String> limitations) { }
    public record View(String id, String state, String fileId, long findingId, String ruleId, long reviewId,
                       String sourceRevision, long revision, String originalHash, String currentHash,
                       int startLine, String before, String after, String diff, Provider provider,
                       String explanation, List<String> verificationSteps, List<String> limitations,String flowFindingId,String method) { }
    static final class Session {
        final String id = UUID.randomUUID().toString();
        final String fileId, rule, source, originalHash, currentHash, before;
        String after,diff;
        ResponsePatchValidator.Contract responseContract;
        final String flowFindingId;
        final long findingId, revision;
        final int line, offset;
        final Provider provider;
        String method(){return DETERMINISTIC.equals(provider)?"DETERMINISTIC_FIX":"AI_ASSISTED";}
        String state="APPROVAL_REQUIRED", explanation="코드는 전송되지 않았습니다.";
        List<String> checks=List.of(), limits=List.of("저장소 설정의 변경 제안입니다. 운영 적용·기능 호환성·취약점 해결은 검증하지 않았습니다.");
        Session(Prepare request, String rule, String source, String currentHash, int line, int offset,
                String before, String after, String diff, Provider provider) {
            this.fileId=request.fileId();this.findingId=request.findingId();this.revision=request.revision();
            this.originalHash=request.originalHash();this.currentHash=currentHash;this.rule=rule;this.source=source;
            this.flowFindingId=request.flowFindingId();
            this.line=line;this.offset=offset;this.before=before;this.after=after;this.diff=diff;this.provider=provider;
        }
    }
    static record Target(String before, String after, int line, int offset) { }
    private static final Pattern PROPERTY=Pattern.compile("^([ \\t]*)([a-zA-Z0-9_.-]+)([ \\t]*[=:][ \\t]*)([a-zA-Z]+)([ \\t]*)$");
    static Target target(String original, String current, int findingLine, String rule, String path) {
        if(!path.endsWith(".properties") || original==null || current==null)throw new IllegalArgumentException();
        original=normalize(original);current=normalize(current);
        String[] lines=original.split("\n",-1);
        if(findingLine<1||findingLine>lines.length)throw new IllegalArgumentException();
        String before=lines[findingLine-1]; var match=PROPERTY.matcher(before);
        if(!match.matches()||before.getBytes(StandardCharsets.UTF_8).length>512)throw new IllegalArgumentException();
        String key=match.group(2), old=match.group(4), value;
        if(rule.equals("DEBUG_ENABLED")&&key.equals("debug")&&old.equals("true"))value="false";
        else if(rule.equals("STACKTRACE_EXPOSURE")&&key.equals("server.error.include-stacktrace")&&old.equals("always"))value="never";
        else if(rule.equals("INSECURE_COOKIE")&&Set.of("server.servlet.session.cookie.secure","server.servlet.session.cookie.http-only")
                .contains(key)&&old.equals("false"))value="true";
        else throw new IllegalArgumentException();
        int offset=0, selected=-1, selectedLine=0, keyCount=0, number=0;
        // Escapes/continuations and duplicate keys need richer properties semantics; abstain.
        for(String line:current.split("\n",-1)) {
            number++;String trimmed=line.stripLeading();
            if(!trimmed.startsWith("#")&&!trimmed.startsWith("!")) {
                if(line.contains("\\"))throw new IllegalArgumentException();
                if(line.matches("[ \\t]*"+Pattern.quote(key)+"(?:[ \\t:=].*|$)"))keyCount++;
            }
            if(line.equals(before)){if(selected>=0)throw new IllegalArgumentException();selected=offset;selectedLine=number;}
            offset+=line.length()+1;
        }
        if(selected<0||keyCount!=1)throw new IllegalArgumentException();
        String after=match.group(1)+key+match.group(3)+value+match.group(5);
        return new Target(before,after,selectedLine,selected);
    }
    static String normalize(String value) { return (value.startsWith("\ufeff")?value.substring(1):value).replace("\r\n","\n"); }
    public static void validate(Output output, View expected) {
        var sanitizer=new RemediationSanitizer();
        if(output==null || !Set.of("PATCH","NEEDS_REVIEW").contains(output.decision())
                || !expected.fileId().equals(output.fileId()) || output.startLine()!=expected.startLine()
                || !SourceArchive.hash(expected.before().getBytes(StandardCharsets.UTF_8)).equals(output.expectedHash()))throw new IllegalArgumentException();
        if(output.explanation()==null||output.explanation().isBlank()||output.explanation().length()>600
                || !output.explanation().equals(sanitizer.text(output.explanation(),600))
                || output.verificationSteps()==null || output.verificationSteps().isEmpty() || output.verificationSteps().size()>6
                || output.limitations()==null || output.limitations().size()>6)throw new IllegalArgumentException();
        for(String text:java.util.stream.Stream.concat(output.verificationSteps().stream(),output.limitations().stream()).toList())
            if(text==null||text.isBlank()||text.length()>400||!text.equals(sanitizer.text(text,400)))throw new IllegalArgumentException();
        // Properties keep the server-derived constant; TypeScript also needs the separate AST contract check.
        if("PATCH".equals(output.decision())) {
            if(expected.flowFindingId()==null&&!Objects.equals(expected.after(),output.replacement()))throw new IllegalArgumentException();
            if(expected.flowFindingId()!=null&&(output.replacement()==null||output.replacement().isBlank()||output.replacement().length()>4096
                    ||!output.replacement().equals(sanitizer.text(output.replacement(),4096))
                    ||output.replacement().contains("<redacted>")||output.replacement().contains("[omitted]")))throw new IllegalArgumentException();
        }
        if("NEEDS_REVIEW".equals(output.decision())&&!"".equals(output.replacement()))throw new IllegalArgumentException();
    }
    public static Map<String,Object> schema() {
        var string=Map.<String,Object>of("type","string");
        var props=new LinkedHashMap<String,Object>();props.put("decision",Map.of("type","string","enum",List.of("PATCH","NEEDS_REVIEW")));
        props.put("fileId",string);props.put("startLine",Map.of("type","integer"));props.put("expectedHash",string);
        for(String key:List.of("replacement","explanation"))props.put(key,string);
        for(String key:List.of("verificationSteps","limitations"))props.put(key,Map.of("type","array","items",string));
        return Map.of("type","object","properties",props,"required",List.copyOf(props.keySet()),"additionalProperties",false);
    }
    public static Output parse(com.fasterxml.jackson.databind.JsonNode root) {
        if(root==null||!root.isObject()||root.size()!=8||!root.path("startLine").isIntegralNumber()||!root.path("startLine").canConvertToInt())throw new IllegalArgumentException();
        for(String field:List.of("decision","fileId","expectedHash","replacement","explanation"))
            if(!root.path(field).isTextual()||root.path(field).textValue().length()>(field.equals("replacement")?4096:1024))throw new IllegalArgumentException();
        var lists=new ArrayList<List<String>>();
        for(String field:List.of("verificationSteps","limitations")) {
            var array=root.path(field);if(!array.isArray()||array.size()>6)throw new IllegalArgumentException();
            var result=new ArrayList<String>();for(var item:array){if(!item.isTextual()||item.textValue().length()>400)throw new IllegalArgumentException();result.add(item.textValue());}lists.add(List.copyOf(result));
        }
        return new Output(root.path("decision").textValue(),root.path("fileId").textValue(),root.path("startLine").intValue(),root.path("expectedHash").textValue(),root.path("replacement").textValue(),root.path("explanation").textValue(),lists.get(0),lists.get(1));
    }
}
