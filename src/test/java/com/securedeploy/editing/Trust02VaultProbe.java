package com.securedeploy.editing;
import com.fasterxml.jackson.databind.ObjectMapper;import org.springframework.jdbc.core.JdbcTemplate;import org.springframework.jdbc.datasource.DriverManagerDataSource;import java.time.*;import java.util.*;
/** Read-only diagnostic for this task's synthetic DB and separate test key only. */
public final class Trust02VaultProbe {
 public static void main(String[] args)throws Exception{
  if(args.length!=2||!args[0].matches("[1-9][0-9]*")||!args[1].contains("SecureDeploy_TRUST02_PRIVATE_20261101/keys/"))throw new IllegalArgumentException("CONTROL_ONLY");
  var mapper=new ObjectMapper().findAndRegisterModules();var ds=new DriverManagerDataSource("jdbc:postgresql://127.0.0.1:58550/trust02_fixture","ai05_fixture","");ds.setConnectionProperties(new Properties(){{setProperty("options","-c default_transaction_read_only=on");}});
  var vault=new WorkspaceVault(new JdbcTemplate(ds),mapper,true,"","trust02-test-v1",86400,args[1]);var loaded=vault.owner(Long.parseLong(args[0]),Instant.now()).orElseThrow();var s=loaded.snapshot();
  System.out.println(mapper.writeValueAsString(Map.of("revision",s.revision(),"storeVersion",loaded.version(),"files",s.files().stream().map(f->Map.of("id",f.id(),"path",f.path(),"currentHash",SourceArchive.hash(f.edit()==null?f.original():f.edit()),"originalHash",f.hash(),"origin",f.origin(),"history",f.provenance().size())).toList(),"exports",s.exports().size(),"expiresAt",s.expires().toString())));
 }
}
