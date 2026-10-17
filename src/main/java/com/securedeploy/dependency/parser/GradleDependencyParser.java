package com.securedeploy.dependency.parser;

import com.securedeploy.dependency.model.DependencyEcosystem;
import com.securedeploy.dependency.model.DependencyInfo;
import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.sca.parser.GradleManifestParser;
import com.securedeploy.sca.model.VersionResolution;
import java.util.List;

public class GradleDependencyParser {

    public List<DependencyInfo> parse(ProjectFile file) {
        try {
            return new GradleManifestParser().parse(file).stream()
                    .filter(d -> d.versionResolution() == VersionResolution.EXACT)
                    .map(d -> new DependencyInfo(d.packageName(), d.version(), DependencyEcosystem.GRADLE,
                            d.sourceFile(), d.line())).toList();
        } catch (IllegalArgumentException unsupportedManifest) {
            // SCA records the same parser failure/size limit; this catalog rule must not abort other rules.
            return List.of();
        }
    }

}
