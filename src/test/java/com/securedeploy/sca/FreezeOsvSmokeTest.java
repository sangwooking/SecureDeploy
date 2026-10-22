package com.securedeploy.sca;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedeploy.project.model.ProjectStructure;
import com.securedeploy.sca.client.OsvClient;
import com.securedeploy.sca.config.ScaProperties;
import com.securedeploy.sca.model.ScaResult;
import com.securedeploy.sca.parser.ScaManifestCollector;
import com.securedeploy.sca.service.ScaService;
import java.io.*;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.http.*;
import org.springframework.http.client.*;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

/** Opt-in public identities only; live records are replayed through the same SCA service. */
@EnabledIfEnvironmentVariable(named="FREEZE_OSV_SMOKE", matches="true")
class FreezeOsvSmokeTest {
    record Exchange(String uri,HttpMethod method,byte[] request,byte[] response) { }
    @Test void livePublicPackagesRoundTripAndReplayWithoutAdditionalNetworkCalls() throws Exception {
        var json=new ObjectMapper().findAndRegisterModules();
        var config=new ScaProperties(true,5,25,3,8);
        var factory=new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(5000);factory.setReadTimeout(5000);
        var captured=new ArrayList<Exchange>();
        var live=RestClient.builder().baseUrl("https://api.osv.dev").requestFactory(factory)
                .requestInterceptor((request,body,execution)->{
                    if(captured.size()>=9)throw new IOException("SMOKE_REQUEST_LIMIT");
                    var response=execution.execute(request,body);
                    try {
                        byte[] bytes=response.getBody().readNBytes(2_000_001);
                        if(bytes.length>2_000_000||!response.getStatusCode().is2xxSuccessful())throw new IOException("SMOKE_RESPONSE_INVALID");
                        captured.add(new Exchange(request.getURI().toString(),request.getMethod(),body,bytes));
                        var status=response.getStatusCode();var headers=response.getHeaders();
                        return new ClientHttpResponse(){
                            public HttpStatusCode getStatusCode(){return status;}
                            public String getStatusText(){return "OK";}
                            public HttpHeaders getHeaders(){return headers;}
                            public InputStream getBody(){return new ByteArrayInputStream(bytes);}
                            public void close(){ }
                        };
                    } finally {response.close();}
                }).build();
        var project=new ProjectStructure(Path.of("."),List.of(ScaParserTest.file("package.json","""
            {"dependencies":{"lodash":"4.17.20","is-number":"7.0.0","securedeploy-nonexistent-smoke-package-20261022":"1.0.0"}}
            """)));
        var result=new ScaService(new ScaManifestCollector(json),new OsvClient(live,json,config),config).analyze(project);
        assertThat(result.status()).isEqualTo(ScaResult.Status.COMPLETE);
        assertThat(result.summary().dependenciesAnalyzed()).isEqualTo(3);
        assertThat(result.dependencyVulnerabilities()).anyMatch(v->v.packageName().equals("lodash")&&v.osvId().equals("GHSA-35jh-r3h4-6jhm"));
        assertThat(result.dependencyVulnerabilities()).noneMatch(v->v.packageName().equals("is-number"));
        assertThat(result.dependencyVulnerabilities()).noneMatch(v->v.packageName().startsWith("securedeploy-nonexistent"));
        var snapshot=json.readValue(json.writeValueAsBytes(result),ScaResult.class);
        assertThat(snapshot).isEqualTo(result);
        var replayBuilder=RestClient.builder().baseUrl("https://api.osv.dev");
        var replay=MockRestServiceServer.bindTo(replayBuilder).build();
        for(var call:captured){
            var expected=replay.expect(requestTo(call.uri())).andExpect(method(call.method()));
            if(call.request().length>0)expected.andExpect(content().bytes(call.request()));
            expected.andRespond(withSuccess(call.response(),MediaType.APPLICATION_JSON));
        }
        var repeated=new ScaService(new ScaManifestCollector(json),new OsvClient(replayBuilder.build(),json,config),config).analyze(project);
        assertThat(repeated.dependencyVulnerabilities()).isEqualTo(result.dependencyVulnerabilities());
        assertThat(repeated.summary()).isEqualTo(result.summary());assertThat(repeated.status()).isEqualTo(result.status());
        replay.verify();
        // An empty advisory response does not prove that a package exists or is globally safe.
        System.out.printf("FREEZE_OSV requests=%d analyzed=%d advisories=%d emptyResponses=2 snapshotRoundTrip=true replayEqual=true%n",
                captured.size(),result.summary().dependenciesAnalyzed(),result.dependencyVulnerabilities().size());
    }
}
