package ready02fixture;
import java.net.*;import java.net.http.*;import java.util.*;import java.nio.file.*;import com.fasterxml.jackson.databind.ObjectMapper;import org.springframework.boot.builder.SpringApplicationBuilder;import org.springframework.jdbc.core.JdbcTemplate;import com.securedeploy.persistence.repository.UserRepository;import com.securedeploy.auth.security.JwtTokenProvider;
public class OperatingCopyProbe {
 public static void main(String[]args)throws Exception {
  if(System.getenv("OPENAI_API_KEY")!=null||System.getenv("SECUREDEPLOY_AI_OPENAI_API_KEY")!=null)throw new IllegalStateException();
  var c=new SpringApplicationBuilder(com.securedeploy.SecureDeployApplication.class).run("--server.address=127.0.0.1","--server.port=0","--spring.datasource.url=jdbc:postgresql://127.0.0.1:58220/ready02_oper_copy","--spring.datasource.username=ai05_fixture","--spring.datasource.password=","--spring.datasource.driver-class-name=org.postgresql.Driver","--spring.jpa.hibernate.ddl-auto=validate","--spring.sql.init.mode=never","--securedeploy.jwt.secret=ready02-synthetic-copy-only-signing-key-000001","--securedeploy.ai.provider=TEMPLATE","--securedeploy.ai.openai.api-key=","--securedeploy.github.app.enabled=false","--securedeploy.threat-intelligence.enabled=false","--logging.level.root=OFF","--spring.main.banner-mode=off");
  try{var jdbc=c.getBean(JdbcTemplate.class);var before=inventory(jdbc);var http=HttpClient.newHttpClient();int port=((org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext)c).getWebServer().getPort();var mapper=new ObjectMapper();int projects=0,reviews=0,foreign=0,sca=0;var users=c.getBean(UserRepository.class).findAll();var tokens=c.getBean(JwtTokenProvider.class);
   for(var user:users){String token=tokens.createToken(user);
    for(String list:List.of("/api/projects","/api/reviews"))if(get(http,port,list,token).statusCode()!=200)throw new AssertionError("OWNER_LIST");
    var owned=jdbc.queryForList("select id from projects where user_id=?",Long.class,user.getId());
    for(long id:owned){if(get(http,port,"/api/projects/"+id,token).statusCode()!=200)throw new AssertionError("OWNER_PROJECT");projects++;}
    var rows=jdbc.queryForList("select r.id from reviews r join projects p on p.id=r.project_id where p.user_id=?",Long.class,user.getId());
    for(long id:rows){var r=get(http,port,"/api/reviews/"+id,token);if(r.statusCode()!=200)throw new AssertionError("OWNER_REVIEW");if(!mapper.readTree(r.body()).path("sca").isNull())sca++;reviews++;}
    var others=jdbc.queryForList("select id from projects where user_id<>?",Long.class,user.getId());for(long id:others){int status=get(http,port,"/api/projects/"+id,token).statusCode();if(status!=403&&status!=404)throw new AssertionError("FOREIGN_PROJECT");foreign++;}
   }
   if(!before.equals(inventory(jdbc)))throw new AssertionError("COPY_ROWS_CHANGED");
   var result=Map.of("passed",true,"usersChecked",users.size(),"ownedProjectsRead",projects,"ownedReviewsRead",reviews,"scaReviewsRead",sca,"foreignProjectsDenied",foreign,"rowHashesUnchanged",true,"authMethod","ISOLATED_TEST_JWT_NOT_PASSWORD_LOGIN","productionWrites",false);
   Files.writeString(Path.of("/private/tmp/securedeploy-ready02-evidence/OPERATING_COPY_COMPATIBILITY.json"),mapper.writeValueAsString(result));System.out.println(mapper.writeValueAsString(result));
  }finally{c.close();}
 }
 static HttpResponse<String> get(HttpClient client,int port,String path,String token)throws Exception{return client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+path)).header("Authorization","Bearer "+token).GET().build(),HttpResponse.BodyHandlers.ofString());}
 static Map<String,String> inventory(JdbcTemplate db){var result=new TreeMap<String,String>();for(String t:List.of("users","projects","reviews","vulnerabilities"))result.put(t,db.queryForObject("select md5(coalesce(string_agg(h,'' order by h),'')) from(select md5(row_to_json(t)::text) h from "+t+" t)x",String.class));return result;}
}
