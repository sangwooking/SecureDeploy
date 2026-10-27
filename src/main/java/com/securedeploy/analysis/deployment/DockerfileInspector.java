package com.securedeploy.analysis.deployment;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.project.coverage.CoverageRecorder;
import com.securedeploy.rule.rules.*;
import java.util.*;

final class DockerfileInspector {
    static DeploymentSnapshot.FileResult inspect(ProjectFile file) {
        var observations=new ArrayList<DeploymentSnapshot.Observation>();var limits=new ArrayList<String>(List.of(
                "DEFAULT_FINAL_STAGE_ONLY_COMPOSE_TARGET_AND_USER_NOT_MERGED","IMAGE_CONTENTS_LAYERS_SBOM_AND_REGISTRY_NOT_INSPECTED",
                "BUILD_SECRET_MOUNT_NOT_COPY_OR_LOG_PROTECTION","COPY_CONTEXT_DOCKERIGNORE_AND_SYMLINKS_NOT_INSPECTED","LIMITED_ENV_NOT_COMPLETE_DOCKERFILE_VALIDATION"));
        if(file.lines().stream().mapToLong(s->s.length()+1L).sum()>100_000)return new DeploymentSnapshot.FileResult(CoverageRecorder.safePath(file.relativePath()),"DOCKERFILE","LIMIT_EXCEEDED",List.of(),List.of("CONFIG_RESOURCE_LIMIT"));
        var user=DockerRuntimeUser.inspect(file);boolean known=user.status()!=DockerRuntimeUser.Status.UNKNOWN;
        observations.add(new DeploymentSnapshot.Observation(user.line(),"default-final-stage","runtime_user",known?"STATIC":"UNKNOWN",user.reason(),""));
        var env=DockerEnvironment.inspect(file);
        if(!env.complete())limits.add("DOCKER_ENV_SYNTAX_OR_BUDGET_NOT_RESOLVED");
        for(var d:env.declarations())observations.add(new DeploymentSnapshot.Observation(d.line(),"build-declaration",d.kind().equals("EMPTY")?"empty_credential_env":"credential_env",
                env.complete()&&!d.kind().equals("DYNAMIC")?"STATIC":"UNKNOWN",d.kind().equals("EMPTY")?"empty value declaration":d.kind().equals("LITERAL")?"non-empty credential-name declaration; value omitted":"value source unresolved",""));
        for(var d:env.traits())observations.add(new DeploymentSnapshot.Observation(d.line(),"build-declaration",d.kind(),env.complete()?"STATIC":"UNKNOWN","declaration only; runtime effect not inspected",""));
        return new DeploymentSnapshot.FileResult(CoverageRecorder.safePath(file.relativePath()),"DOCKERFILE",env.complete()?"PARSED":"PARTIAL",List.copyOf(observations),List.copyOf(limits));
    }
}
