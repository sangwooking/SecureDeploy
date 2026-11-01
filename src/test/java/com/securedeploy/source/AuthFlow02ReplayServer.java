package com.securedeploy.source;
import com.securedeploy.SecureDeployApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
/** Manual evaluation only; captured official feed, never an operating datasource. */
public final class AuthFlow02ReplayServer {
 public static void main(String[] args){
  for(String arg:args)if(arg.startsWith("--spring.datasource.url=")&&!arg.equals("--spring.datasource.url=jdbc:postgresql://127.0.0.1:58550/auth_flow02_fixture"))throw new IllegalArgumentException("ISOLATED_DB_ONLY");
  new SpringApplicationBuilder(SecureDeployApplication.class,Harden01ReplayServer.Replay.class).run(args);
 }
}
