package com.securedeploy.rule.rules;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.analysis.typescript.TypeScriptAnalysisProperties;
import com.securedeploy.project.model.ProjectStructure;
import com.securedeploy.rule.model.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import org.springframework.stereotype.Component;

/** Shared bounded string-context reconciliation; missing evidence never removes a warning. */
@Component
public final class InsecureApiUrlContext {
    private static final String VERSION = "string-context-v4";
    private final TypeScriptAnalysisProperties properties;
    private final Semaphore capacity = new Semaphore(2);
    private final ObjectMapper mapper = new ObjectMapper();
    public InsecureApiUrlContext(TypeScriptAnalysisProperties properties) { this.properties=properties; }

    public List<RuleMatch> reconcile(ProjectStructure project, List<RuleMatch> matches) {
        var paths=matches.stream().filter(m->Set.of("INSECURE_API_URL","HARDCODED_FRONTEND_SECRET","UNVALIDATED_REDIRECT","REACT_DANGEROUS_HTML").contains(m.ruleId()))
                .map(RuleMatch::filePath).collect(java.util.stream.Collectors.toSet());
        if(paths.isEmpty())return matches;
        List<Map<String,Object>> files=new ArrayList<>();
        Map<String,Integer> lineCounts=new HashMap<>();int total=0;
        for(var f:project.analysisFiles().stream().sorted(Comparator.comparing(x->x.relativePath())).toList()) {
            if(!(paths.contains(f.relativePath())||f.lines().stream().anyMatch(s->s.contains("from 'i18next'")||s.contains("from \"i18next\"")))||!(RuleFileTypes.isFrontendSource(f)||f.type()==com.securedeploy.project.model.ProjectFileType.FRONTEND_CONFIG))continue;
            long length=f.lines().stream().mapToLong(s->s.length()+1L).sum();
            int bounded=(int)Math.min(length,250_000);
            if(total+bounded>1_000_000||files.size()>=100)continue;
            var text=new StringBuilder(bounded);
            for(String line:f.lines()) {
                int available=250_000-text.length();if(available<=0)break;
                if(!text.isEmpty()){text.append('\n');available--;}
                text.append(line,0,Math.min(line.length(),available));
            }
            files.add(Map.of("filePath",f.relativePath(),"content",text.toString(),"prefixOnly",length>250_000));
            lineCounts.put(f.relativePath(),f.lines().size());total+=bounded;
        }
        Map<String,Set<Integer>> excluded=new HashMap<>(),requests=new HashMap<>(),secrets=new HashMap<>(),redirects=new HashMap<>(),html=new HashMap<>();
        if(properties.isEnabled()&&!files.isEmpty()&&capacity.tryAcquire()) {
            Process process=null;
            var io=Executors.newFixedThreadPool(2,r->{var t=new Thread(r,"url-context-io");t.setDaemon(true);return t;});
            try {
                Path directory=Path.of(properties.getAnalyzerDirectory()).toRealPath();
                if(!Files.isRegularFile(directory.resolve("url-context-worker.mjs")))throw new IllegalStateException();
                var builder=new ProcessBuilder(properties.getNodeExecutable(),"--permission","--no-addons",
                        "--max-old-space-size=192","--allow-fs-read="+directory,directory.resolve("url-context-worker.mjs").toString());
                builder.directory(directory.toFile());builder.environment().clear();builder.environment().put("LANG","en_US.UTF-8");
                builder.redirectError(ProcessBuilder.Redirect.DISCARD);process=builder.start();Process child=process;
                byte[] input=mapper.writeValueAsBytes(Map.of("files",files));
                var writer=io.submit(()->{try(var stream=child.getOutputStream()){stream.write(input);}return true;});
                var reader=io.submit(()->child.getInputStream().readNBytes(200_001));
                if(!process.waitFor(properties.getTimeoutSeconds(),TimeUnit.SECONDS))throw new IllegalStateException();
                writer.get(1,TimeUnit.SECONDS);byte[] output=reader.get(1,TimeUnit.SECONDS);
                if(process.exitValue()!=0||output.length>200_000)throw new IllegalStateException();
                JsonNode result=mapper.readTree(output);
                if(!VERSION.equals(result.path("version").asText())||!"6.0.3".equals(result.path("parserVersion").asText())
                        ||!result.path("files").isArray()||result.path("files").size()!=files.size())throw new IllegalStateException();
                Set<String> seen=new HashSet<>();
                for(var row:result.path("files")) {
                    String path=row.path("filePath").asText();
                    if(!lineCounts.containsKey(path)||!seen.add(path))throw new IllegalStateException();
                    if(!Set.of("PARSED","PREFIX_COMMENTS_ONLY").contains(row.path("status").asText()))continue;
                    excluded.put(path,lines(row.path("excludedLines"),lineCounts.get(path)));
                    secrets.put(path,lines(row.path("excludedSecretLines"),lineCounts.get(path)));
                    requests.put(path,lines(row.path("requestLines"),lineCounts.get(path)));
                    redirects.put(path,row.has("excludedRedirectLines")?lines(row.path("excludedRedirectLines"),lineCounts.get(path)):Set.of());
                    html.put(path,row.has("excludedHtmlLines")?lines(row.path("excludedHtmlLines"),lineCounts.get(path)):Set.of());
                    if(!Collections.disjoint(excluded.get(path),requests.get(path)))throw new IllegalStateException();
                }
            } catch(InterruptedException failure) {
                Thread.currentThread().interrupt();excluded.clear();requests.clear();secrets.clear();redirects.clear();html.clear();
            } catch(Exception failure) {
                excluded.clear();requests.clear();secrets.clear();redirects.clear();html.clear();
            } finally {
                if(process!=null&&process.isAlive()) {
                    process.destroyForcibly();
                    try{process.waitFor(2,TimeUnit.SECONDS);}catch(InterruptedException ignored){Thread.currentThread().interrupt();}
                }
                io.shutdownNow();capacity.release();
            }
        }
        List<RuleMatch> result=new ArrayList<>();
        for(var match:matches) {
            if(match.ruleId().equals("UNVALIDATED_REDIRECT")&&redirects.getOrDefault(match.filePath(),Set.of()).contains(match.line()))continue;
            if(match.ruleId().equals("REACT_DANGEROUS_HTML")&&html.getOrDefault(match.filePath(),Set.of()).contains(match.line()))continue;
            if(match.ruleId().equals("HARDCODED_FRONTEND_SECRET")&&secrets.getOrDefault(match.filePath(),Set.of()).contains(match.line()))continue;
            if(!match.ruleId().equals("INSECURE_API_URL")){result.add(match);continue;}
            if(excluded.getOrDefault(match.filePath(),Set.of()).contains(match.line()))continue;
            boolean request=requests.getOrDefault(match.filePath(),Set.of()).contains(match.line());
            result.add(match.withFalsePositiveAnalysis(match.severity(),request?FalsePositiveRisk.LOW:FalsePositiveRisk.MEDIUM,
                    request?DetectionConfidence.HIGH:DetectionConfidence.LOW,
                    request?"HTTP 요청 호출의 주소 문자열을 확인했습니다. 실제 운영 통신과 TLS 종료 위치는 별도로 확인해야 합니다."
                    :"HTTP 주소 문자열은 확인했지만 실제 API 요청에 사용되는지 확인하지 못했습니다. 서버 주소 표시·설정·외부 호출과 운영 TLS 구성을 직접 확인해 주세요."));
        }
        return List.copyOf(result);
    }

    private static Set<Integer> lines(JsonNode node,int max) {
        if(!node.isArray()||node.size()>max)throw new IllegalArgumentException();
        Set<Integer> result=new HashSet<>();
        for(var n:node) {
            if(!n.isIntegralNumber()||!n.canConvertToInt()||n.asInt()<1||n.asInt()>max||!result.add(n.asInt()))throw new IllegalArgumentException();
        }
        return result;
    }
}
