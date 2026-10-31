package com.securedeploy.editing;

import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.databind.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import org.springframework.stereotype.Component;

/** Public registry metadata only. Bounded, no redirects, credentials, npmrc or project text. */
@Component
public class NpmRegistry {
    private final ObjectMapper json;
    public NpmRegistry(ObjectMapper json){this.json=json;}
    public List<JsonNode> releases(String name,String current)throws Exception{
        var result=new ArrayList<JsonNode>();
        try(var input=body(name,null);var parser=json.getFactory().createParser(input)){
            if(parser.nextToken()!=JsonToken.START_OBJECT)throw new IllegalArgumentException("REGISTRY_FORMAT");
            while(parser.nextToken()!=JsonToken.END_OBJECT){String key=parser.currentName();parser.nextToken();
                if(!"versions".equals(key)){parser.skipChildren();continue;}
                if(parser.currentToken()!=JsonToken.START_OBJECT)throw new IllegalArgumentException("REGISTRY_VERSIONS");int count=0;
                while(parser.nextToken()!=JsonToken.END_OBJECT){String version=parser.currentName();parser.nextToken();if(++count>50000)throw new IllegalArgumentException("REGISTRY_VERSION_LIMIT");
                    if(NpmTreePlanner.upgrade(current,version)){JsonNode data=json.readTree(parser);if(data.path("version").asText().equals(version)&&data.path("name").asText().equals(name)&&(!data.hasNonNull("deprecated")||data.path("deprecated").asText().isBlank()))result.add(data);}
                    else parser.skipChildren();
                    result.sort(Comparator.comparing(n->n.path("version").asText(),NpmTreePlanner::compare));if(result.size()>64)result.remove(result.size()-1);
                }
            }
        }
        return List.copyOf(result);
    }
    public JsonNode version(String name,String version)throws Exception{
        if(!name.matches("(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+")||!version.matches("[0-9]+\\.[0-9]+\\.[0-9]+(?:-[A-Za-z0-9.-]+)?"))throw new IllegalArgumentException("REGISTRY_ID");
        try(var input=body(name,version)){var node=json.readTree(input);if(!name.equals(node.path("name").asText())||!version.equals(node.path("version").asText()))throw new IllegalArgumentException("REGISTRY_IDENTITY");return node;}
    }
    protected java.io.InputStream body(String name,String version)throws Exception{
        var uri=URI.create("https://registry.npmjs.org/"+URLEncoder.encode(name,StandardCharsets.UTF_8)+(version!=null?"/"+URLEncoder.encode(version,StandardCharsets.UTF_8):""));
        var connection=(java.net.HttpURLConnection)uri.toURL().openConnection(java.net.Proxy.NO_PROXY);connection.setInstanceFollowRedirects(false);connection.setConnectTimeout(5000);connection.setReadTimeout(8000);connection.setRequestProperty("Accept",version==null?"application/vnd.npm.install-v1+json":"application/json");connection.setRequestProperty("User-Agent","SecureDeploy-SCA03/1.0");
        try{int status=connection.getResponseCode();if(status!=200)throw new IllegalArgumentException("REGISTRY_HTTP_"+status);long deadline=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(12);try(var body=connection.getInputStream();var bytes=new java.io.ByteArrayOutputStream()){byte[] buffer=new byte[8192];int count;while((count=body.read(buffer))!=-1){if(System.nanoTime()>deadline)throw new IllegalArgumentException("REGISTRY_TIMEOUT");if(bytes.size()+count>40*1024*1024)throw new IllegalArgumentException("REGISTRY_SIZE_LIMIT");bytes.write(buffer,0,count);}return new java.io.ByteArrayInputStream(bytes.toByteArray());}}finally{connection.disconnect();}
    }
}
