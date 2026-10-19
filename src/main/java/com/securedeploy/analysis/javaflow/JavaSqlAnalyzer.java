package com.securedeploy.analysis.javaflow;

import com.securedeploy.project.model.ProjectStructure;
import com.securedeploy.project.model.ProjectFileType;
import com.securedeploy.project.coverage.CoverageRecorder;
import com.securedeploy.rule.model.RuleMatch;
import org.springframework.stereotype.Service;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;

@Service
public class JavaSqlAnalyzer {
    private final Semaphore capacity=new Semaphore(2);
    public record Outcome(List<RuleMatch> matches, JavaSqlSnapshot snapshot) { }

    public JavaSqlWorker.Result analyze(ProjectStructure project) {
        var files=project.analysisFiles().stream().filter(f->f.type()==ProjectFileType.JAVA)
                .sorted(Comparator.comparingInt((com.securedeploy.project.model.ProjectFile f)->
                        f.lines().stream().anyMatch(l->l.contains("@RestController")||l.contains("@Controller")||l.contains("HttpServlet"))?0:1)
                        .thenComparing(f->f.relativePath())).toList();
        if(files.isEmpty())return unavailable("NOT_APPLICABLE",List.of(),"NO_JAVA_FILES");
        var sources=new ArrayList<JavaSqlWorker.Source>();var omitted=new ArrayList<JavaSqlWorker.FileResult>();
        var lineCounts=new HashMap<String,Integer>();int total=0;
        for(var file:files) {
            String path=CoverageRecorder.safePath(file.relativePath());
            long size=file.lines().stream().mapToLong(l->l.length()+1L).sum();
            if(sources.size()>=100||size>100_000||total+size>1_000_000||path.equals("[redacted-path]")||path.length()>1024) {
                if(omitted.size()<100)omitted.add(new JavaSqlWorker.FileResult(path,"LIMIT_EXCEEDED",0,0,0,0,List.of("SOURCE_SELECTION_LIMIT")));
            } else {sources.add(new JavaSqlWorker.Source(path,String.join("\n",file.lines())));total+=(int)size;lineCounts.put(path,file.lines().size());}
        }
        var notRun=new ArrayList<>(omitted);sources.forEach(s->notRun.add(new JavaSqlWorker.FileResult(s.path(),"NOT_RUN",0,0,0,0,List.of())));
        if(sources.isEmpty())return unavailable("UNAVAILABLE",notRun,"NO_JAVA_SOURCE_WITHIN_LIMITS");
        if(!capacity.tryAcquire())return unavailable("UNAVAILABLE",notRun,"ANALYZER_CAPACITY_LIMIT");
        Path directory=null;Process process=null;
        var io=Executors.newFixedThreadPool(2,r->{var t=new Thread(r,"java-sql-io");t.setDaemon(true);return t;});
        try {
            directory=Files.createTempDirectory("securedeploy-java-parser-");
            Path jar=directory.resolve("worker.jar");
            try(var input=JavaSqlAnalyzer.class.getResourceAsStream("/analyzers/java-sql-worker.jar")) {
                if(input==null)return unavailable("UNAVAILABLE",notRun,"TRUSTED_WORKER_NOT_PACKAGED");
                Files.copy(input,jar);
            }
            var bytes=new ByteArrayOutputStream();
            try(var input=new DataOutputStream(bytes)) {
                input.writeInt(sources.size());
                for(var source:sources){byte[] text=source.content().getBytes(StandardCharsets.UTF_8);input.writeUTF(source.path());input.writeInt(text.length);input.write(text);}
            }
            var builder=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin","java").toString(),
                    "-Xmx192m","-Xss1m","-XX:MaxMetaspaceSize=96m","-XX:ActiveProcessorCount=1","-jar",jar.toString());
            builder.directory(directory.toFile());builder.environment().clear();builder.environment().put("LANG","en_US.UTF-8");
            builder.redirectError(ProcessBuilder.Redirect.DISCARD);process=builder.start();Process child=process;
            var writer=io.submit(()->{try(var out=child.getOutputStream()){out.write(bytes.toByteArray());}return null;});
            var reader=io.submit(()->{try(var in=child.getInputStream()){return in.readNBytes(2_000_001);}});
            if(!process.waitFor(8,TimeUnit.SECONDS))return unavailable("TIMEOUT",notRun,"JAVA_PARSER_TIMEOUT");
            writer.get(1,TimeUnit.SECONDS);byte[] output=reader.get(1,TimeUnit.SECONDS);
            if(process.exitValue()!=0||output.length>2_000_000)return unavailable("UNAVAILABLE",notRun,"JAVA_WORKER_FAILED");
            JavaSqlWorker.Result result;
            try(var input=new DataInputStream(new ByteArrayInputStream(output))){result=JavaSqlWorker.read(input);if(input.read()!=-1)throw new IOException("TRAILING_OUTPUT");}
            validate(result,lineCounts);
            var coverage=new ArrayList<>(result.files());coverage.addAll(omitted);var notes=new ArrayList<>(result.limitations());
            if(files.size()>sources.size())notes.add("SOURCE_SELECTION_LIMIT");
            if(files.size()>sources.size()+omitted.size())notes.add("OMITTED_FILE_DETAILS_TRUNCATED");
            return new JavaSqlWorker.Result(result.version(),result.status(),coverage,result.methods(),result.uses(),notes);
        } catch(InterruptedException interrupted){Thread.currentThread().interrupt();return unavailable("UNAVAILABLE",notRun,"ANALYSIS_INTERRUPTED");}
        catch(Exception failed){return unavailable("UNAVAILABLE",notRun,"JAVA_WORKER_OR_PROTOCOL_FAILED");}
        finally {
            if(process!=null&&process.isAlive()){process.destroyForcibly();try{process.waitFor(2,TimeUnit.SECONDS);}catch(InterruptedException e){Thread.currentThread().interrupt();}}
            io.shutdownNow();if(directory!=null)com.securedeploy.global.util.FileUtils.deleteRecursively(directory);capacity.release();
        }
    }

    public Outcome reconcile(List<RuleMatch> raw,JavaSqlWorker.Result result) {
        var remaining=new ArrayList<RuleMatch>();var refs=new ArrayList<JavaSqlSnapshot.LegacyEvidence>();
        int suppressed=0;
        for(var match:raw) {
            if(!match.ruleId().equals("DANGEROUS_SQL")){remaining.add(match);continue;}
            boolean safe=result.methods().stream().anyMatch(m->m.safeForLegacy()&&m.filePath().equals(match.filePath())&&m.startLine()<=match.line()&&m.endLine()>=match.line());
            if(safe){suppressed++;continue;}
            var linked=result.uses().stream().filter(u->u.kind().equals("INPUT_IN_QUERY")&&related(match,u)).map(JavaSqlWorker.Use::location).toList();
            if(!linked.isEmpty())refs.add(new JavaSqlSnapshot.LegacyEvidence(match.filePath(),match.line(),linked));
            remaining.add(match);
        }
        // Merge only legacy signals with one identical, statically traced execution anchor.
        var anchors=new HashSet<String>();
        remaining.removeIf(m->{
            var ref=refs.stream().filter(r->r.filePath().equals(m.filePath())&&r.line()==m.line()).findFirst();
            if(!m.ruleId().equals("DANGEROUS_SQL")||ref.isEmpty()||ref.get().executions().size()!=1)return false;
            var l=ref.get().executions().get(0);return !anchors.add(l.filePath()+":"+l.line()+":"+l.column());
        });
        var candidates=new ArrayList<JavaSqlSnapshot.Candidate>();
        for(var use:result.uses())if(use.kind().equals("INPUT_IN_QUERY")&&use.limitations().isEmpty()
                &&use.trace().stream().anyMatch(l->Set.of("REQUEST_INPUT","REQUEST_COOKIE","COOKIE_VALUE").contains(l.kind()))
                &&remaining.stream().noneMatch(m->m.ruleId().equals("DANGEROUS_SQL")&&related(m,use))) {
            var l=use.location();
            candidates.add(new JavaSqlSnapshot.Candidate(identity(l),"JAVA_SQL_INPUT_FLOW","REVIEW_REQUIRED","NOT_COMPARED",l,use.trace(),
                    "사용자가 보낸 값이 SQL 명령문에 들어갈 수 있습니다",
                    "요청 입력이 SQL 구성과 실행 호출까지 전달되는 정적 경로를 확인했습니다. 실제 공격 성공·DB 연결·외부 검증은 확인하지 않았습니다.",
                    "SQL 문법을 고정하고 값은 PreparedStatement의 set 메서드 또는 JdbcTemplate 매개변수로 분리하세요. 테이블·열 이름은 서버의 고정된 선택지로 제한하세요.",
                    List.of("입력·SQL 구성·실행 위치와 외부 검증 계층을 확인하세요.","로컬 테스트에서 정상 값과 따옴표·SQL 문법 입력이 값으로만 처리되는지 확인하세요.","수정 후 같은 프로젝트를 재검사하세요. 이 새 후보는 기존 점수·Risk·해결 수에 합산되지 않습니다.")));
        }
        return new Outcome(List.copyOf(remaining),new JavaSqlSnapshot(result,List.copyOf(candidates),suppressed,List.copyOf(refs)));
    }
    private boolean related(RuleMatch m,JavaSqlWorker.Use use) {
        return use.location().filePath().equals(m.filePath())&&(use.location().line()==m.line()
                ||use.trace().stream().anyMatch(l->l.filePath().equals(m.filePath())&&l.line()==m.line()));
    }
    private String identity(JavaSqlWorker.Location l) {
        try{return "java-sql:"+HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest((JavaSqlWorker.VERSION+":"+l.filePath()+":"+l.line()+":"+l.column()).getBytes(StandardCharsets.UTF_8)));}
        catch(Exception impossible){throw new IllegalStateException("IDENTITY_UNAVAILABLE");}
    }
    private JavaSqlWorker.Result unavailable(String status,List<JavaSqlWorker.FileResult> files,String reason){return new JavaSqlWorker.Result(JavaSqlWorker.VERSION,status,files,List.of(),List.of(),List.of(reason));}
    private void validate(JavaSqlWorker.Result r,Map<String,Integer> files) throws IOException {
        if(!r.version().equals(JavaSqlWorker.VERSION)||!Set.of("PARTIAL","NOT_APPLICABLE").contains(r.status())
                ||r.files().size()!=files.size()||!r.files().stream().map(JavaSqlWorker.FileResult::filePath).collect(java.util.stream.Collectors.toSet()).equals(files.keySet()))throw new IOException("INVALID_WORKER_RESULT");
        for(var m:r.methods())if(!files.containsKey(m.filePath())||m.startLine()<1||m.endLine()<m.startLine()||m.endLine()>files.get(m.filePath()))throw new IOException("INVALID_METHOD");
        for(var u:r.uses()) {
            if(!Set.of("INPUT_IN_QUERY","STATIC_QUERY","PARAMETERIZED_QUERY","UNRESOLVED_QUERY").contains(u.kind()))throw new IOException("INVALID_USE");
            var locations=new ArrayList<>(u.trace());locations.add(u.location());
            for(var l:locations)if(!files.containsKey(l.filePath())||l.line()<1||l.line()>files.get(l.filePath())||l.column()<1||l.column()>100_001||l.functionName().length()>100)throw new IOException("INVALID_LOCATION");
        }
    }
}
