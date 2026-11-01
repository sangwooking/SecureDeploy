package com.securedeploy.editing;
import com.fasterxml.jackson.databind.ObjectMapper;import org.springframework.jdbc.core.JdbcTemplate;import org.springframework.jdbc.datasource.DriverManagerDataSource;import java.time.*;
/** Explicit owned-test expiration fixture, never a product endpoint or operating datasource. */
public final class Trust01ExpiryFixture {
 public static void main(String[] args)throws Exception{
  if(args.length!=2||!args[0].matches("[1-9][0-9]*")||!args[1].equals("/Users/sangwoo__o/Documents/조렁ㅂㅏ품/SecureDeploy_TRUST01_PRIVATE_20261101/keys/synthetic-only.key"))throw new IllegalArgumentException("CONTROL_ONLY");
  var v=new WorkspaceVault(new JdbcTemplate(new DriverManagerDataSource("jdbc:postgresql://127.0.0.1:58550/trust01_fixture","ai05_fixture","")),new ObjectMapper().findAndRegisterModules(),true,"","trust01-test-v1",86400,args[1]);
  var old=v.owner(Long.parseLong(args[0]),Instant.now()).orElseThrow();var s=old.snapshot();var expires=Instant.now().plusSeconds(4);
  v.put(new WorkspaceVault.Snapshot(s.format(),s.id(),s.owner(),s.project(),s.review(),s.revision(),s.created(),expires,s.source(),s.identity(),s.files(),s.exports()),old.version());System.out.println(expires);
 }
}
