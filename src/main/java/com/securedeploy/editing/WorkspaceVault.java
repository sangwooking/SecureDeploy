package com.securedeploy.editing;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.global.error.SecureDeployException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.*;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/** Versioned, opt-in encrypted storage. No schema DDL, keys, sources or provider requests in logs. */
@Component
public class WorkspaceVault {
    record File(String id,String path,byte[] original,boolean directory,int mode,String hash,byte[] edit,
                String origin,List<ChangeAttribution> provenance) { }
    record Snapshot(int format,String id,long owner,long project,long review,long revision,Instant created,Instant expires,
                    String source,String identity,List<File> files,List<EditingWorkspaceService.ExportApproval> exports) { }
    record Loaded(Snapshot snapshot,long version) { }
    private static final int MAX_ENVELOPE=48*1024*1024;
    private final boolean enabled;
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final byte[] key;
    private final String keyId;
    private final Duration retention;
    private boolean auditEnabled;
    private org.springframework.transaction.support.TransactionTemplate auditTx;
    record Write(String requestId,String fileId,String hash,Long beforeRevision,String type) { }
    record Event(String eventId,String workspaceId,long ownerId,long projectId,long reviewId,String type,Instant at,Instant expiresAt,Long beforeRevision,Long afterRevision,long storeVersion,String requestId,String fileId,String currentHash,String outcome,String executionPath) { }
    @org.springframework.beans.factory.annotation.Autowired
    void configureAudit(@Value("${securedeploy.editing.audit.enabled:false}") boolean active) {
        if(active&&!enabled)throw new IllegalStateException("Workspace audit requires persistent storage");
        if(active){jdbc.queryForObject("select count(*) from editing_workspace_event_v1 where 1=0",Long.class);
            auditTx=new org.springframework.transaction.support.TransactionTemplate(new org.springframework.jdbc.datasource.DataSourceTransactionManager(Objects.requireNonNull(jdbc.getDataSource())));}
        auditEnabled=active;
    }
    boolean audited(){return auditEnabled;}
    private final SecureRandom random=new SecureRandom();

    public WorkspaceVault(JdbcTemplate jdbc,ObjectMapper mapper,boolean enabled,String encoded,String keyId,long retentionSeconds){this(jdbc,mapper,enabled,encoded,keyId,retentionSeconds,"");}
    @org.springframework.beans.factory.annotation.Autowired
    public WorkspaceVault(JdbcTemplate jdbc,ObjectMapper mapper,
            @Value("${securedeploy.editing.persistence.enabled:false}") boolean enabled,
            @Value("${securedeploy.editing.persistence.key:}") String encoded,
            @Value("${securedeploy.editing.persistence.key-id:}") String keyId,
            @Value("${securedeploy.editing.persistence.retention-seconds:86400}") long retentionSeconds,
            @Value("${securedeploy.editing.persistence.key-file:}") String keyFile) {
        this.jdbc=jdbc;this.mapper=mapper;this.enabled=enabled;this.keyId=keyId;
        this.retention=Duration.ofSeconds(retentionSeconds);
        if(!enabled){key=null;return;}
        try {
            if(!keyFile.isBlank()){
                if(!encoded.isBlank())throw new IllegalArgumentException();
                var file=java.nio.file.Path.of(keyFile);
                var options=new java.nio.file.LinkOption[]{java.nio.file.LinkOption.NOFOLLOW_LINKS};
                if(!file.isAbsolute()||!java.nio.file.Files.isRegularFile(file,options)||java.nio.file.Files.isSymbolicLink(file)||java.nio.file.Files.size(file)>128)throw new IllegalArgumentException();
                var permissions=java.nio.file.Files.getPosixFilePermissions(file,options);
                if(!permissions.equals(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"))
                    ||!java.nio.file.Files.getPosixFilePermissions(file.getParent()).equals(java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"))
                    ||!java.nio.file.Files.getOwner(file,options).getName().equals(System.getProperty("user.name"))
                    ||((Number)java.nio.file.Files.getAttribute(file,"unix:nlink",options)).intValue()!=1)throw new IllegalArgumentException();
                encoded=java.nio.file.Files.readString(file,StandardCharsets.US_ASCII).trim();
            }
            key=Base64.getDecoder().decode(encoded);
            if(key.length!=32||!keyId.matches("[A-Za-z0-9_-]{1,64}")||retentionSeconds<1800||retentionSeconds>30*86400)throw new IllegalArgumentException();
            // Fail startup rather than silently creating schema or falling back to plaintext.
            jdbc.queryForObject("select count(*) from editing_workspace_v1 where 1=0",Long.class);
        }catch(Exception invalid){throw new IllegalStateException("Workspace persistence requires its explicit migration and a valid separate key/configuration");}
    }
    boolean enabled(){return enabled;}
    Duration retention(){return enabled?retention:Duration.ofMinutes(30);}
    Optional<Loaded> owner(long owner,Instant now){
        if(!enabled)return Optional.empty();
        var rows=jdbc.query("select id,project_id,review_id,store_version,expires_at,key_id,payload from editing_workspace_v1 where owner_id=? and expires_at>?",
            (r,n)->decode(r.getString(1),owner,r.getLong(2),r.getLong(3),r.getLong(4),r.getTimestamp(5).toInstant(),r.getString(6),r.getBytes(7)),owner,java.sql.Timestamp.from(now));
        return rows.stream().findFirst();
    }
    long put(Snapshot s,long expected){return put(s,expected,null);}
    long put(Snapshot s,long expected,Write write){
        if(auditEnabled)return auditTx.execute(status->putInternal(s,expected,write));
        return putInternal(s,expected,write);
    }
    private long putInternal(Snapshot s,long expected,Write write){
        if(!enabled)return 0;
        validate(s);
        long next=expected+1;
        byte[] encrypted=encrypt(s,next);
        try {
            int changed;
            if(expected==0)changed=jdbc.update("insert into editing_workspace_v1(id,owner_id,project_id,review_id,store_version,expires_at,key_id,payload) values(?,?,?,?,?,?,?,?)",
                s.id,s.owner,s.project,s.review,next,java.sql.Timestamp.from(s.expires),keyId,encrypted);
            else changed=jdbc.update("update editing_workspace_v1 set store_version=?,expires_at=?,key_id=?,payload=? where id=? and owner_id=? and project_id=? and review_id=? and store_version=?",
                next,java.sql.Timestamp.from(s.expires),keyId,encrypted,s.id,s.owner,s.project,s.review,expected);
            if(changed!=1)throw conflict();
            if(auditEnabled)event(s.id,s.owner,s.project,s.review,expected==0?"CREATED":write==null?"MUTATED":write.type,Instant.now(),s.expires,write==null?null:write.beforeRevision,s.revision,next,write==null?null:write.requestId,write==null?null:write.fileId,write==null?null:write.hash,"COMMITTED","USER_REQUEST");
            return next;
        }catch(org.springframework.dao.DataIntegrityViolationException race){throw conflict();}
        finally {Arrays.fill(encrypted,(byte)0);}
    }
    void delete(String id,long owner,long version){
        if(!enabled)return;
        if(!auditEnabled){if(jdbc.update("delete from editing_workspace_v1 where id=? and owner_id=? and store_version=?",id,owner,version)!=1)throw conflict();return;}
        auditTx.executeWithoutResult(tx->{var rows=jdbc.queryForList("select id,owner_id,project_id,review_id,store_version,expires_at from editing_workspace_v1 where id=? and owner_id=? and store_version=? for update",id,owner,version);if(rows.size()!=1)throw conflict();remove(rows.get(0),"DELETED","USER_REQUEST",Instant.now());});
    }
    void cleanupOwner(long owner,Instant now){if(!enabled)return;if(!auditEnabled){jdbc.update("delete from editing_workspace_v1 where owner_id=? and expires_at<=?",owner,java.sql.Timestamp.from(now));return;}clean(owner,now);}
    int cleanup(Instant now){if(!enabled)return 0;if(!auditEnabled)return jdbc.update("delete from editing_workspace_v1 where id in (select id from editing_workspace_v1 where expires_at<=? order by expires_at limit 100)",java.sql.Timestamp.from(now));return clean(null,now);}
    private int clean(Long owner,Instant now){return auditTx.execute(tx->{
        var rows=owner==null?jdbc.queryForList("select id,owner_id,project_id,review_id,store_version,expires_at from editing_workspace_v1 where expires_at<=? order by expires_at limit 100 for update skip locked",java.sql.Timestamp.from(now)):
            jdbc.queryForList("select id,owner_id,project_id,review_id,store_version,expires_at from editing_workspace_v1 where owner_id=? and expires_at<=? order by expires_at limit 100 for update skip locked",owner,java.sql.Timestamp.from(now));
        for(var row:rows)remove(row,"EXPIRED",owner==null?"SCHEDULED_EXPIRY":"OWNER_ACQUIRE_EXPIRY",now);
        // Fixed 30-day audit retention; bounded sweep, independent of source retention.
        jdbc.update("delete from editing_workspace_event_v1 where event_id in (select event_id from editing_workspace_event_v1 where occurred_at<? order by occurred_at limit 500)",java.sql.Timestamp.from(now.minus(Duration.ofDays(30))));return rows.size();});}
    private void remove(Map<String,Object> row,String type,String path,Instant now){
        String id=(String)row.get("id");long owner=((Number)row.get("owner_id")).longValue(),project=((Number)row.get("project_id")).longValue(),review=((Number)row.get("review_id")).longValue(),version=((Number)row.get("store_version")).longValue();
        if(jdbc.update("delete from editing_workspace_v1 where id=? and owner_id=? and store_version=?",id,owner,version)!=1)throw conflict();
        event(id,owner,project,review,type,now,((java.sql.Timestamp)row.get("expires_at")).toInstant(),null,null,version,null,null,null,"COMMITTED",path);
    }
    private void event(String id,long owner,long project,long review,String type,Instant at,Instant expires,Long before,Long after,long version,String request,String file,String hash,String outcome,String path){
        jdbc.update("insert into editing_workspace_event_v1(event_id,workspace_id,owner_id,project_id,review_id,event_type,occurred_at,expires_at,before_revision,after_revision,store_version,request_id,file_id,current_hash,outcome,execution_path) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",UUID.randomUUID().toString(),id,owner,project,review,type,java.sql.Timestamp.from(at),java.sql.Timestamp.from(expires),before,after,version,request,file,hash,outcome,path);
    }
    List<Event> events(String id,long owner){return readEvents(id,owner,null);}
    Optional<Event> receipt(String id,long owner,String request){if(request==null)return Optional.empty();return readEvents(id,owner,request).stream().findFirst();}
    private List<Event> readEvents(String id,long owner,String request){if(!auditEnabled)return List.of();
        String sql="select * from editing_workspace_event_v1 where workspace_id=? and owner_id=?"+(request==null?"":" and request_id=?")+" order by occurred_at desc,event_id desc limit 100";
        return jdbc.query(sql,(r,n)->new Event(r.getString("event_id"),r.getString("workspace_id"),r.getLong("owner_id"),r.getLong("project_id"),r.getLong("review_id"),r.getString("event_type"),r.getTimestamp("occurred_at").toInstant(),r.getTimestamp("expires_at").toInstant(),(Long)r.getObject("before_revision"),(Long)r.getObject("after_revision"),r.getLong("store_version"),r.getString("request_id"),r.getString("file_id"),r.getString("current_hash"),r.getString("outcome"),r.getString("execution_path")),request==null?new Object[]{id,owner}:new Object[]{id,owner,request});}
    Optional<Loaded> stored(String id,long owner){if(!enabled)return Optional.empty();return jdbc.query("select project_id,review_id,store_version,expires_at,key_id,payload from editing_workspace_v1 where id=? and owner_id=?",(r,n)->decode(id,owner,r.getLong(1),r.getLong(2),r.getLong(3),r.getTimestamp(4).toInstant(),r.getString(5),r.getBytes(6)),id,owner).stream().findFirst();}
    private byte[] aad(String id,long owner,long project,long review,long version,Instant expiry,String kid){
        return ("securedeploy-workspace-v1|"+id+"|"+owner+"|"+project+"|"+review+"|"+version+"|"+expiry+"|"+kid).getBytes(StandardCharsets.UTF_8);
    }
    private byte[] encrypt(Snapshot s,long version){
        byte[] plain=null;
        try {
            plain=mapper.writeValueAsBytes(s);
            if(plain.length>MAX_ENVELOPE-28)throw SourceArchive.limit();
            byte[] nonce=new byte[12];random.nextBytes(nonce);
            var cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));
            cipher.updateAAD(aad(s.id,s.owner,s.project,s.review,version,s.expires,keyId));
            var encrypted=cipher.doFinal(plain);var out=new byte[12+encrypted.length];
            System.arraycopy(nonce,0,out,0,12);System.arraycopy(encrypted,0,out,12,encrypted.length);return out;
        }catch(SecureDeployException limit){throw limit;}
        catch(Exception failure){throw unavailable();}
        finally{if(plain!=null)Arrays.fill(plain,(byte)0);}
    }
    private Loaded decode(String id,long owner,long project,long review,long version,Instant expires,String kid,byte[] payload){
        byte[] plain=null;
        try {
            if(!keyId.equals(kid)||payload.length<28||payload.length>MAX_ENVELOPE)throw new IllegalArgumentException();
            var cipher=Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,Arrays.copyOf(payload,12)));
            cipher.updateAAD(aad(id,owner,project,review,version,expires,kid));
            plain=cipher.doFinal(payload,12,payload.length-12);
            var s=mapper.readValue(plain,Snapshot.class);validate(s);
            if(!s.id.equals(id)||s.owner!=owner||s.project!=project||s.review!=review||!s.expires.equals(expires))throw new IllegalArgumentException();
            return new Loaded(s,version);
        }catch(Exception invalid){throw unavailable();}
        finally{if(plain!=null)Arrays.fill(plain,(byte)0);Arrays.fill(payload,(byte)0);}
    }
    private void validate(Snapshot s){
        if(s.format!=1||s.revision<1||s.owner<=0||s.project<=0||s.review<=0||!s.id.matches("[0-9a-f-]{36}")||!s.expires.isAfter(s.created)||s.files==null||s.exports==null||s.exports.size()>128)throw new IllegalArgumentException();
        SourceArchive.validate(s.files.stream().map(f->new SourceArchive.Entry(f.path,f.original,f.directory,f.mode)).toList());
        var ids=new HashSet<String>();long bytes=0;int history=0;
        for(var f:s.files){
            if(!ids.add(f.id)||!f.id.matches("[0-9a-f-]{36}")||!SourceArchive.hash(f.original).equals(f.hash)||f.provenance==null)throw new IllegalArgumentException();
            if(f.edit!=null&&(SourceArchive.text(f.original)==null||SourceArchive.text(f.edit)==null))throw new IllegalArgumentException();
            bytes+=f.original.length+(f.edit==null?0:f.edit.length);history+=f.provenance.size();
        }
        if(bytes>SourceArchive.MAX_BYTES||history>1024)throw SourceArchive.limit();
    }
    private EditingConflictException conflict(){return new EditingConflictException("WORKSPACE_REVISION_CONFLICT","다른 요청에서 저장한 내용이 있습니다. 현재 편집을 내보낸 뒤 최신 내용을 확인해 주세요.");}
    private SecureDeployException unavailable(){return new SecureDeployException(HttpStatus.SERVICE_UNAVAILABLE,"저장된 작업 공간의 암호화 키 또는 무결성을 확인할 수 없습니다. 원본을 덮어쓰지 않고 관리자 확인을 기다립니다.");}
}
