package com.securedeploy.release;
import com.securedeploy.ai.config.*;import org.springframework.context.annotation.Profile;import org.springframework.stereotype.Component;import org.springframework.core.env.Environment;import org.springframework.jdbc.core.JdbcTemplate;
/** Conflicting command-line overrides cannot silently enable paid/automated work in fallback. */
@Component @Profile("release-compatible")
public class CompatibleConfigurationGuard {
 public CompatibleConfigurationGuard(AiProperties ai,Environment env,JdbcTemplate db){
  if(ai.getProvider()!=AiProviderType.TEMPLATE||env.getProperty("securedeploy.ai.ledger.enabled",Boolean.class,false)||env.getProperty("securedeploy.ai.patch-policy.external-enabled",Boolean.class,false)||env.getProperty("securedeploy.editing.automation-enabled",Boolean.class,true)||env.getProperty("securedeploy.editing.npm-generation-enabled",Boolean.class,false))throw new IllegalStateException("Compatible mode requires TEMPLATE and disabled automation/paid generation");
  if(!env.getProperty("securedeploy.editing.persistence.enabled",Boolean.class,false)){
   boolean exists=Boolean.TRUE.equals(db.queryForObject("select exists(select 1 from information_schema.tables where table_schema='public' and table_name='editing_workspace_v1')",Boolean.class));
   if(exists&&db.queryForObject("select count(*) from editing_workspace_v1",Long.class)>0)throw new IllegalStateException("Encrypted workspaces require their original key and persistence in compatible mode");
  }
 }
}
