package com.securedeploy.sca.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.auth.service.ReviewAccessService;
import com.securedeploy.sca.model.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Read-only plans from saved evidence. No model, network, source writes or risk reassessment. */
@Service
public class DependencyUpdatePlanService {
    public record Location(String file, int line, String section, String parentPackage,
                           String declaredVersion, boolean confirmed, boolean optional, boolean peer) { }
    public record Plan(String ecosystem, String packageName, String lockedVersion, String advisoryId,
                       List<String> aliases, List<DependencyVulnerability.AdvisoryRange> affectedRanges,
                       String advisoryModified, List<String> referenceUrls, List<String> sourceFiles,
                       String dependencyKind, List<Location> locations, List<String> fixedVersionEvidence,
                       List<String> sameMajorCandidates, String packageManagerEvidence, String action,
                       String status, boolean patchApplicable, String compatibility, String lockfileStatus,
                       String explanation, List<String> verificationSteps, List<String> unknowns) { }
    public record Snapshot(int schemaVersion, long reviewId, String sourceRevision, Instant analyzedAt,
                           String evidenceHash, String origin, String modelVerification,
                           List<Plan> plans, List<String> limitations) { }
    private final ReviewAccessService access;
    private final ObjectMapper mapper;
    public DependencyUpdatePlanService(ReviewAccessService access, ObjectMapper mapper) { this.access=access;this.mapper=mapper; }

    @Transactional(readOnly=true)
    public Snapshot get(long reviewId) {
        // Authorize even when no SCA result exists; never accept client-provided advisory facts.
        var review=access.findAccessibleReviewWithVulnerabilities(reviewId,"분석 결과에 접근할 수 없습니다.");
        var sca=review.getScaResult();
        String sha=review.getSourceMetadata()==null?null:review.getSourceMetadata().commitSha();
        return build(reviewId,sha,sca);
    }
    Snapshot build(long reviewId,String sha,ScaResult sca) {
        var plans=new ArrayList<Plan>();
        if(sca!=null&&sca.dependencyVulnerabilities()!=null) {
            // Preserve each advisory/package/version tuple rather than treating the count as update tasks.
            for(var dep:sca.dependencyVulnerabilities()) {
                var matches=sca.components()==null?List.<DependencyComponent>of():sca.components().stream()
                        .filter(c->c.ecosystem()==dep.ecosystem()&&Objects.equals(c.packageName(),dep.packageName())
                                &&Objects.equals(c.version(),dep.installedVersion())&&c.versionResolution()==VersionResolution.EXACT).toList();
                var locations=new LinkedHashSet<Location>();
                for(var c:matches)if(c.context()!=null&&c.context().paths()!=null)for(var p:c.context().paths())
                    locations.add(new Location(p.declarationFile(),p.declarationLine(),p.declarationSection(),p.declaredPackage(),p.declaredVersion(),p.declarationConfirmed(),p.optional(),p.peer()));
                var fixed=copy(dep.fixedVersions());
                boolean direct=matches.stream().anyMatch(c->Boolean.TRUE.equals(c.direct()));
                boolean indirect=matches.stream().anyMatch(c->Boolean.FALSE.equals(c.direct()));
                String kind=direct&&indirect?"MIXED":direct?"DIRECT":indirect?"TRANSITIVE":"UNKNOWN";
                boolean npm=dep.ecosystem()==ScaEcosystem.NPM;
                boolean lock=npm&&!matches.isEmpty()&&matches.stream().allMatch(c->c.sourceFile()!=null&&c.sourceFile().endsWith("package-lock.json"));
                var candidates=matches.isEmpty()?List.<String>of():fixed.stream().filter(v->sameMajor(dep.installedVersion(),v)).distinct().toList();
                String action=!npm?"UNSUPPORTED_PACKAGE_MANAGER":matches.isEmpty()?"VERIFY_EXACT_VERSION":fixed.isEmpty()?"NO_FIXED_VERSION_EVIDENCE":locations.stream().noneMatch(Location::confirmed)?"VERIFY_DECLARATION":direct?"REVIEW_DIRECT_DECLARATION":"REVIEW_PARENT_OR_SCOPED_OVERRIDE";
                var unknowns=new ArrayList<>(List.of("실제 설치·실행 여부와 정상 기능·API 호환성은 확인하지 않았습니다.",
                        "저장된 공지의 수정 버전은 해당 공지의 근거이며 다른 공지 해결이나 최신 상태를 보증하지 않습니다.",
                        "상위 패키지의 호환 버전, peer 충돌, 전체 workspace 및 패키지 관리자 버전은 실제 파일로 확인해야 합니다."));
                if(!lock)unknowns.add("유효한 npm lockfile 및 패키지 관리자 계약을 확인하지 못했습니다.");
                if(candidates.isEmpty())unknowns.add("동일 major의 정확한 안정 수정 후보를 확인하지 못했습니다. 임의 최신 버전을 추천하지 않습니다.");
                if(matches.stream().anyMatch(c->c.context()==null||!c.context().pathsComplete()))unknowns.add("상위 의존성 경로가 일부 또는 전부 미확인입니다.");
                plans.add(new Plan(dep.ecosystem().name(),dep.packageName(),dep.installedVersion(),dep.osvId(),copy(dep.aliases()),
                        dep.affectedRanges()==null?List.of():List.copyOf(dep.affectedRanges()),dep.modified(),copy(dep.referenceUrls()),copy(dep.sourceFiles()),
                        kind,List.copyOf(locations),fixed,candidates,lock?"NPM_LOCK_OBSERVED_VERSION_UNVERIFIED":"UNKNOWN",action,
                        "REVIEW_REQUIRED",false,"NOT_VERIFIED","REGENERATION_NOT_VERIFIED",
                        "저장된 버전과 보안 공지가 연결되어 있습니다. "+(indirect?"다른 패키지의 설치 경로에 포함되어 있어 상위 선언이나 범위를 제한한 override를 검토해야 합니다.":"직접 선언과 잠금 버전을 대조한 뒤 업데이트를 검토하세요.")+" 실제 악용 가능성이 확인된 것은 아닙니다.",
                        List.of("원본 SHA와 manifest·lockfile 해시 및 직접·간접 경로를 확인하세요.",
                                "공식 공지와 registry에서 후보 버전·Node 요구사항·peer 조건을 확인하세요.",
                                "승인된 격리 환경에서 패키지 관리자로 lockfile을 재생성하세요. lockfile의 임의 텍스트 치환은 사용하지 마세요.",
                                "Diff에서 변경 파일·버전·의존성 경로와 새 위험을 확인한 뒤 Workspace에 적용하세요.",
                                "동일한 공지 자료로 재검사하고 빌드·기능 검증 여부를 별도로 기록하세요."),List.copyOf(unknowns)));
            }
        }
        String hash;
        try { hash=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(mapper.writeValueAsBytes(sca))); }
        catch(Exception e){throw new IllegalStateException("SCA evidence cannot be fingerprinted",e);}
        return new Snapshot(1,reviewId,sha,sca==null?null:sca.analyzedAt(),hash,"SAVED_SCA_EVIDENCE","NOT_RUN",List.copyOf(plans),
                List.of("근거 기반 검토 계획이며 AI가 생성한 코드 Patch가 아닙니다. 원본 Finding·Risk·Score를 변경하지 않습니다.",
                        "원본 파일·SHA·해시 및 lockfile 재생성을 검증하기 전에는 승인 가능한 Patch를 제공하지 않습니다."));
    }
    private static List<String> copy(List<String> xs){return xs==null?List.of():List.copyOf(xs);}
    private static boolean sameMajor(String current,String candidate){
        if(current==null||candidate==null||!current.matches("[0-9]+\\.[0-9]+\\.[0-9]+")||!candidate.matches("[0-9]+\\.[0-9]+\\.[0-9]+"))return false;
        var a=current.split("\\.");var b=candidate.split("\\.");
        if(!a[0].equals(b[0])||(a[0].equals("0")&&!a[1].equals(b[1])))return false;
        try {for(int i=1;i<3;i++){int x=Integer.parseInt(a[i]),y=Integer.parseInt(b[i]);if(y!=x)return y>x;}return false;}
        catch(NumberFormatException e){return false;}
    }
}
