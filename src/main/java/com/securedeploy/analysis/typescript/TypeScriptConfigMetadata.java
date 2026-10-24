package com.securedeploy.analysis.typescript;

import com.securedeploy.project.coverage.CoverageRecorder;
import com.securedeploy.project.model.ProjectFile;
import java.util.*;

/** JSONC text is sent only to our trusted parse-only TypeScript parser. */
final class TypeScriptConfigMetadata {
    static List<Map<String,String>> read(List<ProjectFile> files) {
        int remaining=Math.min(128_000,1_000_000-NodeManifestMetadata.read(files).characters());
        var result=new ArrayList<Map<String,String>>();
        for(var f:files.stream().filter(f->f.relativePath().equals("tsconfig.json")||f.relativePath().endsWith("/tsconfig.json"))
                .sorted(Comparator.comparing(ProjectFile::relativePath)).limit(32).toList()) {
            String p=CoverageRecorder.safePath(f.relativePath());if(p.equals("[redacted-path]"))continue;
            long size=f.lines().stream().mapToLong(l->l.length()+1L).sum();
            if(size>64_000||size>remaining){result.add(Map.of("filePath",p,"status","LIMIT_EXCEEDED"));continue;}
            remaining-=(int)size;result.add(Map.of("filePath",p,"status","SELECTED","content",String.join("\n",f.lines())));
        }
        return List.copyOf(result);
    }
}
