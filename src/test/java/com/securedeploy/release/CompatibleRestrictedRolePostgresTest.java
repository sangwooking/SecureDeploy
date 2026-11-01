package com.securedeploy.release;
import static org.junit.jupiter.api.Assertions.*;import org.junit.jupiter.api.Test;import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;import org.springframework.jdbc.core.JdbcTemplate;import org.springframework.jdbc.datasource.DriverManagerDataSource;import org.springframework.mock.env.MockEnvironment;import com.securedeploy.ai.config.AiProperties;
@EnabledIfEnvironmentVariable(named="SECUREDEPLOY_RELEASE_PG_URL",matches="jdbc:postgresql://127\\.0\\.0\\.1:(?:58220/ready02_fixture|58450/v53_fixture|58550/(?:v53_gate_fixture|source01_pgtest|source02_pgtest|sca03_pgtest|v54_pgtest|v55_pgtest|harden01_pgtest|auth_flow01_pgtest))")
class CompatibleRestrictedRolePostgresTest {
 @Test void hiddenWorkspaceTableCannotFallBackToMemory(){
  String url=System.getenv("SECUREDEPLOY_RELEASE_PG_URL"),role="ready02_metadata_probe";var admin=new JdbcTemplate(new DriverManagerDataSource(url,"ai05_fixture",""));admin.execute("create role "+role+" login");
  try{admin.execute("grant usage on schema public to "+role);var restricted=new JdbcTemplate(new DriverManagerDataSource(url,role,""));assertFalse(restricted.queryForObject("select exists(select 1 from information_schema.tables where table_schema='public' and table_name='editing_workspace_v1')",Boolean.class));
   var env=new MockEnvironment().withProperty("securedeploy.editing.automation-enabled","false");assertThrows(RuntimeException.class,()->new CompatibleConfigurationGuard(new AiProperties(),env,restricted));
  }finally{admin.execute("revoke usage on schema public from "+role);admin.execute("drop role "+role);}
 }
}
