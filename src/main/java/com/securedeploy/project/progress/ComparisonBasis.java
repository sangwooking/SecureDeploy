package com.securedeploy.project.progress;
import com.securedeploy.persistence.entity.ReviewEntity;
import com.securedeploy.analysis.typescript.*;
import java.util.*;
/** Comparison-only observations. Original IDs, Risk and NOT_COMPARED policy remain immutable. */
public record ComparisonBasis(String sourceState,String engineState,String message,
        Map<String,String> enginesBefore,Map<String,String> enginesAfter,List<FlowEntry> flowChanges,List<String> limitations,List<InputFile> inputFiles) {
 public record InputFile(String path,String beforeHash,String afterHash,String state){}
 public record FlowEntry(String status,String ruleId,String beforeId,String afterId,
        ServerFlowFinding before,ServerFlowFinding after,String note){}
 static ComparisonEvidence evidence(ReviewEntity r){return r==null||r.getComparisonContext()==null?null:r.getComparisonContext().evidence();}
 static Map<String,String> engines(ReviewEntity r){
  var e=evidence(r);if(e!=null)return e.engines();var out=new TreeMap<String,String>();
  if(r!=null&&r.getComparisonContext()!=null&&r.getComparisonContext().analyzerVersion()!=null)out.put("backend",r.getComparisonContext().analyzerVersion());
  if(r!=null&&r.getServerAnalysis()!=null){out.put("typescript",Objects.toString(r.getServerAnalysis().analyzerVersion(),"UNKNOWN"));if(r.getServerAnalysis().pythonAnalysis()!=null)out.put("python",Objects.toString(r.getServerAnalysis().pythonAnalysis().analyzerVersion(),"UNKNOWN"));}return out;
 }
 static String engineState(ReviewEntity a,ReviewEntity b){var x=engines(a);var y=engines(b);if(x.entrySet().stream().anyMatch(e->y.containsKey(e.getKey())&&!"UNKNOWN".equals(e.getValue())&&!"UNKNOWN".equals(y.get(e.getKey()))&&!e.getValue().equals(y.get(e.getKey()))))return "CHANGED";
  return !x.isEmpty()&&x.equals(y)&&x.keySet().containsAll(Set.of("backend","typescript","python","typescriptArtifact","pythonArtifact","typescriptConfiguration","pythonConfiguration","typescriptParser","pythonParser"))&&!x.containsValue("UNKNOWN")?"SAME":"UNKNOWN";
 }
 static String sourceState(ReviewEntity a,ReviewEntity b){
  if(a==null||b==null)return "UNKNOWN";var x=evidence(a);var y=evidence(b);
  if(x!=null&&y!=null&&x.complete()&&y.complete()&&!x.fileHashes().isEmpty()&&Objects.equals(x.hashAlgorithm(),y.hashAlgorithm())){
   if(x.fileHashes().keySet().equals(y.fileHashes().keySet()))return x.fileHashes().equals(y.fileHashes())?"SAME_ANALYZED_INPUT":"CHANGED_ANALYZED_INPUT";
   return "INPUT_SELECTION_CHANGED";
  }
  var w=b.getComparisonContext()==null?null:b.getComparisonContext().workspaceScan();
  if(w!=null&&w.baselineVerified()&&Objects.equals(a.getId(),w.originalReviewId())&&!w.files().isEmpty())return w.files().stream().anyMatch(f->!Objects.equals(f.originalHash(),f.currentHash()))?"CHANGED_VERIFIED_WORKSPACE":"SAME_VERIFIED_WORKSPACE";
  var g=a.getSourceMetadata();var h=b.getSourceMetadata();if(g!=null&&h!=null&&Objects.equals(g.canonicalRepositoryUrl(),h.canonicalRepositoryUrl())&&g.commitSha()!=null&&g.commitSha().equals(h.commitSha()))return "SAME_GIT_REVISION";
  return "UNKNOWN";
 }
 static boolean changedFile(ReviewEntity a,ReviewEntity b,String path){var x=evidence(a);var y=evidence(b);path=ComparisonContextCollector.normalize(path);
  if(x!=null&&y!=null&&Objects.equals(x.hashAlgorithm(),y.hashAlgorithm())&&x.fileHashes().containsKey(path)&&y.fileHashes().containsKey(path))return !x.fileHashes().get(path).equals(y.fileHashes().get(path));
  var w=b.getComparisonContext()==null?null:b.getComparisonContext().workspaceScan();final String p=path;
  return w!=null&&w.baselineVerified()&&Objects.equals(a.getId(),w.originalReviewId())&&w.files().stream().anyMatch(f->ComparisonContextCollector.normalize(f.path()).equals(p)&&!f.originalHash().equals(f.currentHash()));
 }
 static boolean sameFile(ReviewEntity a,ReviewEntity b,String path){var x=evidence(a);var y=evidence(b);path=ComparisonContextCollector.normalize(path);if(x!=null&&y!=null&&Objects.equals(x.hashAlgorithm(),y.hashAlgorithm())&&x.fileHashes().containsKey(path))return x.fileHashes().get(path).equals(y.fileHashes().get(path));
  var w=b==null||b.getComparisonContext()==null?null:b.getComparisonContext().workspaceScan();final String p=path;return w!=null&&w.baselineVerified()&&a!=null&&Objects.equals(a.getId(),w.originalReviewId())&&w.files().stream().anyMatch(f->ComparisonContextCollector.normalize(f.path()).equals(p)&&f.originalHash().equals(f.currentHash()));}
 static String place(ServerAnalysisSnapshot.Location l){return ComparisonContextCollector.normalize(l.filePath())+"|"+l.line()+"|"+l.column()+"|"+l.functionName()+"|"+l.kind();}
 static String anchor(ServerFlowFinding f){return f.ruleId()+"|"+f.evidence().stream().map(e->place(e.source())+">"+place(e.sink())).sorted().toList();}
 static List<ServerFlowFinding> flows(ReviewEntity r){if(r==null||r.getServerAnalysis()==null)return List.of();var s=r.getServerAnalysis();return java.util.stream.Stream.concat((s.validatedFindings()==null?java.util.stream.Stream.<ServerFlowFinding>empty():s.validatedFindings().stream()),s.pythonAnalysis()==null||s.pythonAnalysis().validatedFindings()==null?java.util.stream.Stream.empty():s.pythonAnalysis().validatedFindings().stream()).filter(f->f!=null&&f.ruleId()!=null&&f.sourceType()!=null&&f.location()!=null&&f.evidence()!=null&&!f.evidence().isEmpty()).toList();}
 static boolean sameAnchors(ReviewEntity a,ReviewEntity b,ServerFlowFinding f){return !f.evidence().isEmpty()&&f.evidence().stream().allMatch(e->java.util.stream.Stream.of(e.source(),e.sink()).allMatch(at->{if(at==null||at.line()<1||at.column()<1)return false;if(sameFile(a,b,at.filePath()))return true;var x=evidence(a);var y=evidence(b);var key=ComparisonContextCollector.normalize(at.filePath())+"#"+at.line();return x!=null&&y!=null&&x.anchorHashes().containsKey(key)&&x.anchorHashes().get(key).equals(y.anchorHashes().get(key));}));}
 static boolean observedScope(ReviewEntity before,ReviewEntity after,ServerFlowFinding f){
  if(after==null||after.getServerAnalysis()==null||before.getServerAnalysis()==null)return false;
  var old=f.sourceType().contains("PYTHON")?before.getServerAnalysis().pythonAnalysis():before.getServerAnalysis();var now=f.sourceType().contains("PYTHON")?after.getServerAnalysis().pythonAnalysis():after.getServerAnalysis();if(old==null||now==null)return false;
  var file=now.files().stream().filter(x->x.filePath().equals(f.location().filePath())).findFirst().orElse(null);
  if(file==null||!"PARSED".equals(file.parseStatus())||file.entrypoints()<1||file.limitations().stream().anyMatch(x->x.matches(".*(BUDGET|LIMIT|UNKNOWN|UNRESOLVED|UNSUPPORTED|NOT_MODELED|NOT_SUPPORTED|PARSE_FAILED).*")))return false;
  var entries=old.authorizationContexts().stream().map(c->c.entry()).filter(at->at.filePath().equals(f.location().filePath())).toList();
  return !entries.isEmpty()&&entries.stream().allMatch(at->now.authorizationContexts().stream().anyMatch(c->place(c.entry()).equals(place(at))));
 }
 static List<InputFile> inputFiles(ReviewEntity a,ReviewEntity b){var x=evidence(a);var y=evidence(b);var before=new TreeMap<String,String>();var after=new TreeMap<String,String>();if(x!=null)before.putAll(x.fileHashes());if(y!=null)after.putAll(y.fileHashes());
  var w=b==null||b.getComparisonContext()==null?null:b.getComparisonContext().workspaceScan();if(w!=null&&w.baselineVerified()&&a!=null&&Objects.equals(a.getId(),w.originalReviewId()))for(var f:w.files()){before.putIfAbsent(ComparisonContextCollector.normalize(f.path()),f.originalHash());after.putIfAbsent(ComparisonContextCollector.normalize(f.path()),f.currentHash());}
  var paths=new TreeSet<String>();paths.addAll(before.keySet());paths.addAll(after.keySet());return paths.stream().limit(200).map(p->new InputFile(p,before.get(p),after.get(p),!before.containsKey(p)||!after.containsKey(p)?"UNAVAILABLE":before.get(p).equals(after.get(p))?"SAME":"CHANGED")).toList();
 }
 static boolean previousFileParsed(ReviewEntity r,ServerFlowFinding f){if(r==null||r.getServerAnalysis()==null)return false;var s=f.sourceType().contains("PYTHON")?r.getServerAnalysis().pythonAnalysis():r.getServerAnalysis();return s!=null&&s.findings()!=null&&s.files()!=null&&s.files().stream().anyMatch(file->file.filePath().equals(f.location().filePath())&&"PARSED".equals(file.parseStatus()));}
 static boolean rawObserved(ReviewEntity r,ServerFlowFinding f){if(r==null||r.getServerAnalysis()==null)return false;return java.util.stream.Stream.of(r.getServerAnalysis(),r.getServerAnalysis().pythonAnalysis()).filter(Objects::nonNull).flatMap(s->s.findings()==null?java.util.stream.Stream.<ServerAnalysisSnapshot.Finding>empty():s.findings().stream()).anyMatch(old->old.ruleId().equals(f.ruleId())&&f.evidence().stream().anyMatch(e->place(old.source()).equals(place(e.source()))&&place(old.sink()).equals(place(e.sink()))));}
 static ComparisonBasis compare(ReviewEntity a,ReviewEntity b){String source=sourceState(a,b),engine=engineState(a,b);var old=flows(a);var now=flows(b);var used=new HashSet<ServerFlowFinding>();var entries=new ArrayList<FlowEntry>();
  var oldBy=old.stream().collect(java.util.stream.Collectors.groupingBy(ComparisonBasis::anchor));var nowBy=now.stream().collect(java.util.stream.Collectors.groupingBy(ComparisonBasis::anchor));
  for(var f:old){var matches=nowBy.getOrDefault(anchor(f),List.of());if(matches.size()==1&&oldBy.get(anchor(f)).size()==1&&sameAnchors(a,b,f)){var n=matches.get(0);used.add(n);entries.add(new FlowEntry("OBSERVED_BOTH",f.ruleId(),f.findingId(),n.findingId(),f,n,"동일한 코드 근거에서 두 검사 모두 위험 흐름을 관찰했습니다. ID·엔진 변경을 해결로 처리하지 않습니다."));}
   else{boolean edited="SAME".equals(engine)&&changedFile(a,b,f.location().filePath())&&observedScope(a,b,f)&&matches.isEmpty();entries.add(new FlowEntry(edited?"NOT_REOBSERVED_AFTER_EDIT":"UNAVAILABLE",f.ruleId(),f.findingId(),null,f,null,edited?"변경된 파일의 같은 진입점에서 기존 흐름을 다시 관찰하지 못했습니다. 실제 기능·전체 안전성 또는 확정 해결 판정은 아닙니다.":"엔진·코드 동일성·진입점·분석 범위를 분리할 근거가 부족합니다. 해결로 집계하지 않습니다."));}}
  for(var f:now)if(!used.contains(f)){boolean added="CHANGED".equals(engine)&&source.startsWith("SAME")&&previousFileParsed(a,f)&&!oldBy.containsKey(anchor(f))&&!rawObserved(a,f);entries.add(new FlowEntry(added?"ENGINE_EVIDENCE_ADDED":"UNAVAILABLE",f.ruleId(),null,f.findingId(),null,f,added?"같은 소스에서 새 엔진이 추가 연결한 근거입니다. 코드 변경으로 새로 발생한 위험이라는 뜻은 아닙니다.":"현재 관찰한 흐름이며 코드 변경과 엔진 변경의 영향을 확정 분리하지 못했습니다."));}
  var bounded=new ArrayList<FlowEntry>();int bytes=0;boolean truncated=false;
  var mapper=new com.fasterxml.jackson.databind.ObjectMapper();for(var entry:entries)try{int size=mapper.writeValueAsBytes(entry).length;if(bounded.size()>=200||bytes+size>256000){truncated=true;break;}bounded.add(entry);bytes+=size;}catch(Exception invalid){truncated=true;break;}
  var limitations=new ArrayList<>(List.of("ANALYZED_INPUT_HASHES_NOT_FULL_REPOSITORY_COVERAGE","STRUCTURAL_FLOW_COMPARISON_OUTSIDE_RISK_RESOLVED_NEW_COUNTS","NO_AUTOMATIC_SAFE_OR_RUNTIME_COMPATIBILITY_ASSERTION"));if(truncated)limitations.add("FLOW_COMPARISON_RECORD_OR_BYTE_LIMIT_REVIEW_REQUIRED");
  if((evidence(a)!=null&&evidence(a).fileHashes().size()>200)||(evidence(b)!=null&&evidence(b).fileHashes().size()>200))limitations.add("INPUT_HASH_DISPLAY_LIMIT_200");limitations.add("FLOW_COMPARISON_SCOPE_TS_PY_VALIDATED_FINDINGS_ONLY");limitations.add("EXTERNAL_ADVISORY_DATASET_ID_NOT_RECORDED");
  return new ComparisonBasis(source,engine,"CHANGED".equals(engine)?"분석 엔진이 변경됐습니다. 탐지 차이를 코드 수정 효과로 단정하지 않습니다.":"SAME".equals(engine)?"같은 엔진에서 입력 코드와 확인한 흐름을 비교합니다.":"분석 엔진의 전체 동일성을 확인하지 못했습니다.",engines(a),engines(b),List.copyOf(bounded),List.copyOf(limitations),inputFiles(a,b));
 }
}
