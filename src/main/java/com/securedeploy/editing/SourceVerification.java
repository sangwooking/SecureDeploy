package com.securedeploy.editing;

import com.securedeploy.persistence.entity.ReviewEntity;
import com.securedeploy.source.SourceManifest;
import java.util.*;

/** Identity of the immutable baseline, never a security/safety verdict. */
public record SourceVerification(String status,String message,String scope,boolean recorded,String archiveSha256,
        String commitSha,int fileCount,Retention retention) {
    public record Retention(String storageMode,long seconds,int maxBytes,int maxFiles) { }
    public SourceVerification(String status,String message,String scope,boolean recorded,String archiveSha256,String commitSha,int fileCount){this(status,message,scope,recorded,archiveSha256,commitSha,fileCount,null);}
    SourceVerification withRetention(Retention r){return new SourceVerification(status,message,scope,recorded,archiveSha256,commitSha,fileCount,r);}
    static SourceVerification recorded(ReviewEntity review){var m=manifest(review);return new SourceVerification("UNVERIFIED",m==null?"검사 당시 파일 해시 기록이 부족합니다. 원본 동일성을 아직 확인하지 못했어요.":"검사 당시 해시 기록이 있습니다. 원본을 다시 확보한 뒤 일치 여부를 확인합니다.","ORIGINAL_BYTES_ONLY",m!=null,m==null?null:m.archiveSha256(),m==null?null:m.commitSha(),m==null?0:m.files().size());}
    static SourceManifest manifest(ReviewEntity review){var c=review.getComparisonContext();return c==null?null:c.sourceManifest();}
    static SourceVerification verify(ReviewEntity review,List<SourceArchive.Entry> entries,String archiveHash){
        var m=manifest(review);if(m==null)return recorded(review);
        if(!m.valid())return result("UNVERIFIED","검증 기록 형식을 확인할 수 없습니다.",m);
        boolean differentArchive="ZIP".equals(m.kind())&&archiveHash!=null&&m.archiveSha256()!=null&&!Objects.equals(archiveHash,m.archiveSha256());
        if("GITHUB".equals(m.kind())&&(review.getSourceMetadata()==null||!Objects.equals(m.commitSha(),review.getSourceMetadata().commitSha())))return result("MISMATCH","검사 당시 Commit과 원본 식별자가 다릅니다. 최신 Commit으로 대체하지 않았습니다.",m);
        if(m.files().isEmpty())return result("UNVERIFIED","검사 당시 파일 바이트 해시가 없어 원본 동일성을 확인할 수 없습니다.",m);
        var actual=new HashMap<String,SourceArchive.Entry>();for(var e:entries)if(!e.directory())actual.put(e.path(),e);
        for(var f:m.files()){var e=actual.get(f.path());if(e==null||f.size()!=e.bytes().length||!f.sha256().equals(SourceArchive.hash(e.bytes())))return result("MISMATCH","검사 당시 코드와 확보한 파일이 달라 바로 수정할 수 없어요. 파일 누락·이동·내용 변경을 확인해 주세요.",m);}
        boolean exactFiles=actual.keySet().equals(m.files().stream().map(SourceManifest.File::path).collect(java.util.stream.Collectors.toSet()));
        if(differentArchive){
            if(exactFiles&&m.complete()&&m.analyzedBytesConfirmed())return new SourceVerification("MISMATCH","파일 목록·바이트 해시는 같지만 ZIP 자체는 검사 당시 원본과 다릅니다. 이전 원본 아카이브로 연결하지 않았어요. 원본 ZIP을 선택하거나 이 ZIP으로 새 검사를 시작해 주세요.","FILE_MANIFEST_MATCH_ARCHIVE_MISMATCH",true,m.archiveSha256(),m.commitSha(),m.files().size());
            return result("MISMATCH","ZIP 바이트가 다르고 전체 파일 동일성도 확인하지 못했습니다. 원본 ZIP을 선택하거나 새로 검사해 주세요.",m);
        }
        if(!m.complete()||!m.analyzedBytesConfirmed()||"ZIP".equals(m.kind())&&(archiveHash==null||m.archiveSha256()==null))return result("PARTIAL","일부 원본 해시는 일치하지만 전체 수집·분석 입력 연결을 확인하지 못했습니다. 자동 수정과 과거 행 강조는 제한됩니다.",m);
        if(!exactFiles)return result("MISMATCH","기록된 파일 목록과 확보한 원본이 다릅니다.",m);
        return result("VERIFIED","검사 당시 원본의 바이트·파일 해시 일치를 확인했습니다. 전체 보안·기능 검증을 의미하지 않습니다.",m);
    }
    private static SourceVerification result(String status,String message,SourceManifest m){return new SourceVerification(status,message,"ORIGINAL_BYTES_ONLY",true,m.archiveSha256(),m.commitSha(),m.files().size());}
}
