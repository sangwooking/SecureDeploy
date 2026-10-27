package com.securedeploy.analysis.deployment;

import com.securedeploy.project.model.*;
import com.securedeploy.project.service.ProjectFileCollector;
import com.securedeploy.rule.rules.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

/** Inputs and expectations frozen before #29 product changes; same-author, nonblind Grade B. */
class Supply29ControlsTest {
    record Control(String domain,String id,String truth,String path,String code,String rule,int before,int after,String proof) { }
    static String workflow(String event,String permissions,String steps) {
        return "on: "+event+"\npermissions: "+permissions+"\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n"+steps;
    }
    static final String HEAD="      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n";
    static final List<Control> CASES=List.of(
        new Control("DOCKER","root","RISK","Dockerfile","FROM alpine\nUSER root\n","DOCKER_ROOT_USER",1,1,""),
        new Control("DOCKER","literal","RISK","Dockerfile","FROM alpine\nENV PASSWORD=offline-fixture\n","DOCKER_SECRET_ENV",1,1,""),
        new Control("DOCKER","continued","RISK","Dockerfile","FROM alpine\nENV \\\n  PASSWORD=offline-fixture\n","DOCKER_SECRET_ENV",0,1,""),
        new Control("DOCKER","privileged","RISK","compose.yml","services: {web: {privileged: true}}","DOCKER_PRIVILEGED",1,1,""),
        new Control("DOCKER","socket","RISK","compose.yml","services: {web: {volumes: ['/run/docker.sock:/socket:ro']}}","COMPOSE_SOCKET",1,1,""),
        new Control("DOCKER","arg","RISK","Dockerfile","FROM alpine\nARG PASSWORD=offline-fixture\nRUN echo ready\n","DOCKER_SECRET_ARG",0,0,""),
        new Control("DOCKER","empty","NORMAL","Dockerfile","FROM alpine\nENV PASSWORD=\"\"\n","DOCKER_SECRET_ENV",1,0,"empty_credential_env"),
        new Control("DOCKER","nonroot","NORMAL","Dockerfile","FROM alpine AS builder\nUSER root\nFROM builder\nUSER 1000\n","DOCKER_ROOT_USER",0,0,"NON_ROOT"),
        new Control("DOCKER","secret-mount","NORMAL","Dockerfile","FROM alpine\nRUN --mount=type=secret,id=credential test -f /run/secrets/credential\n","DOCKER_SECRET_ENV",0,0,"build_secret_mount"),
        new Control("DOCKER","expose","NORMAL","Dockerfile","FROM alpine\nEXPOSE 8080\n","COMPOSE_PORT_BINDING",0,0,"expose_declaration"),
        new Control("DOCKER","base","UNKNOWN","Dockerfile","FROM alpine\n","DOCKER_ROOT_USER",0,0,""),
        new Control("DOCKER","dynamic","UNKNOWN","Dockerfile","FROM alpine\nENV PASSWORD=$EXTERNAL_VALUE\n","DOCKER_SECRET_ENV",1,1,""),
        new Control("DOCKER","interpolation","UNKNOWN","compose.yml","services: {web: {privileged: '${ENABLE}'}}","DOCKER_PRIVILEGED",0,0,""),
        new Control("DOCKER","heredoc","UNKNOWN","Dockerfile","FROM alpine\nRUN <<EOF\necho literal\nEOF\n","DOCKER_SECRET_ENV",0,0,""),
        new Control("CI","pr-code","RISK",".github/workflows/check.yml",workflow("pull_request_target","{contents: write}",HEAD+"      - run: npm ci\n"),"CI_UNTRUSTED_PR_EXECUTION",0,1,""),
        new Control("CI","pr-title","RISK",".github/workflows/check.yml",workflow("pull_request","{contents: read}","      - run: echo \"${{ github.event.pull_request.title }}\"\n"),"CI_SCRIPT_EXPRESSION",0,1,""),
        new Control("CI","issue-body","RISK",".github/workflows/check.yml",workflow("issues","{}","      - run: echo \"${{ github.event.issue.body }}\"\n"),"CI_SCRIPT_EXPRESSION",0,1,""),
        new Control("CI","env-eval","RISK",".github/workflows/check.yml",workflow("issues","{}","      - env: {BODY: '${{ github.event.issue.body }}'}\n        run: eval \"$BODY\"\n"),"CI_SCRIPT_EXPRESSION",0,0,""),
        new Control("CI","local-action","NORMAL",".github/workflows/check.yml",workflow("push","{}","      - uses: ./actions/local\n"),"GITHUB_ACTIONS_UNPINNED",1,0,"action_local"),
        new Control("CI","trusted-release","NORMAL",".github/workflows/check.yml",workflow("push","{contents: write}","      - uses: actions/checkout@v4\n      - run: npm ci\n"),"CI_UNTRUSTED_PR_EXECUTION",0,0,"checkout_base"),
        new Control("CI","data-argument","NORMAL",".github/workflows/check.yml",workflow("issues","{}","      - env: {BODY: '${{ github.event.issue.body }}'}\n        run: printf '%s' \"$BODY\"\n"),"CI_SCRIPT_EXPRESSION",0,0,"env_data_argument"),
        new Control("CI","sha-action","NORMAL",".github/workflows/check.yml",workflow("push","{}","      - uses: example/action@0123456789abcdef0123456789abcdef01234567\n"),"GITHUB_ACTIONS_UNPINNED",0,0,"action_sha"),
        new Control("CI","default-permissions","UNKNOWN",".github/workflows/check.yml","on: pull_request_target\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n"+HEAD+"      - run: npm ci\n","CI_UNTRUSTED_PR_EXECUTION",0,0,""),
        new Control("CI","reusable","UNKNOWN",".github/workflows/check.yml","on: push\njobs:\n  check:\n    uses: example/repo/.github/workflows/reuse.yml@v1\n","CI_UNTRUSTED_PR_EXECUTION",0,0,""),
        new Control("CI","conditional","UNKNOWN",".github/workflows/check.yml",workflow("pull_request_target","write-all",HEAD+"      - if: ${{ github.event_name == 'push' }}\n        run: npm ci\n"),"CI_UNTRUSTED_PR_EXECUTION",0,0,""),
        new Control("CI","unknown-action","UNKNOWN",".github/workflows/check.yml",workflow("pull_request_target","{}","      - uses: example/action@v1\n"),"CI_UNTRUSTED_PR_EXECUTION",0,0,"")
    );
    @Test void frozenControlsAndSeparateDomainMetrics() throws Exception {
        boolean before="before".equals(System.getenv("SECUREDEPLOY_SUPPLY29_STAGE"));
        var rows=new ArrayList<Map<String,Object>>();
        for(var c:CASES) {
            var f=new ProjectFile(Path.of("/unopened").resolve(c.path),c.path,new ProjectFileCollector().resolveAnalysisFileType(Path.of(c.path)).orElseThrow(),c.code.lines().toList());
            var snapshot=DeploymentAnalyzer.analyze(new ProjectStructure(Path.of("/unopened"),List.of(f)),null);
            int count=switch(c.rule) {
                case "DOCKER_ROOT_USER" -> new DockerRootUserRule().evaluate(f).size();
                case "DOCKER_SECRET_ENV" -> new DockerSecretEnvRule().evaluate(f).size();
                case "DOCKER_PRIVILEGED" -> new DockerComposeSecurityRule().evaluate(f).size();
                case "GITHUB_ACTIONS_UNPINNED" -> (int)new GitHubActionsSecurityRule().evaluate(f).stream().filter(m->m.ruleId().equals(c.rule)).count();
                default -> (int)snapshot.findings().stream().filter(m->m.ruleId().equals(c.rule)).count();
            };
            assertThat(count).as(c.id).isEqualTo(before?c.before:c.after);
            boolean proof=c.proof.equals("NON_ROOT")?DockerRuntimeUser.inspect(f).status()==DockerRuntimeUser.Status.NON_ROOT_DECLARED
                :!c.proof.isEmpty()&&snapshot.files().stream().flatMap(x->x.observations().stream()).anyMatch(o->o.setting().equals(c.proof)&&o.valueStatus().equals("STATIC"));
            String outcome=c.truth.equals("RISK")?(count>0?"TP":"FN"):c.truth.equals("NORMAL")?(count>0?"FP":proof?"TN":"NORMAL_DEFERRED"):"UNKNOWN";
            rows.add(Map.of("domain",c.domain,"id",c.id,"truth",c.truth,"outcome",outcome,"findingCount",count,"normalProof",proof));
        }
        var result=Map.of("grade","B_SAME_AUTHOR_NONBLIND","rows",rows,"newRealTP",0,"targetExecuted",false);
        String output=System.getenv("SECUREDEPLOY_SUPPLY29_OUTPUT");
        if(output!=null){assertThat(output).startsWith("/private/tmp/securedeploy-supply29-");Files.writeString(Path.of(output),new ObjectMapper().writeValueAsString(result),StandardOpenOption.CREATE_NEW);}
    }
}
