package com.securedeploy.project.coverage;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.project.model.ProjectFileType;
import com.securedeploy.rule.rules.DockerRuntimeUser;
import java.util.*;

/** Snapshot of observed scope, separate from Risk's calculation-completeness and deployment decision. */
public record InspectionScope(int schemaVersion, String assurance, boolean evidenceComplete,
        List<Area> areas, List<String> incompleteAnalyzers) {
    public record Area(String id, String label, String status, int observedFiles,
                       List<String> examplePaths, String limitation) { }

    public static InspectionScope collect(CoverageLedger ledger, List<ProjectFile> files) {
        Map<String, Area> groups = new LinkedHashMap<>();
        for (var entry : ledger.entries()) {
            if (!"FILE".equals(entry.kind()) || "SELECTED".equals(entry.status())) continue;
            String path = entry.filePath().toLowerCase(Locale.ROOT);
            String name = path.substring(path.lastIndexOf('/') + 1);
            String id = null, label = null;
            if (name.endsWith(".py")) { id = "PYTHON_SOURCE"; label = "Python 코드"; }
            else if (com.securedeploy.sca.parser.PythonManifestFiles.isPython(path)) {
                id = "PYTHON_DEPENDENCIES"; label = "Python 의존성";
            } else if (name.endsWith(".dart")) { id = "DART_SOURCE"; label = "Dart 코드"; }
            else if (Set.of("pubspec.yaml", "pubspec.lock").contains(name)) { id = "DART_DEPENDENCIES"; label = "Dart 의존성"; }
            else if (name.equals("podfile") || name.equals("podfile.lock")) { id = "COCOAPODS_DEPENDENCIES"; label = "CocoaPods 의존성"; }
            else if (name.matches(".*\\.(?:mjs|cjs)")) { id = "JAVASCRIPT_SOURCE"; label = "JavaScript 파일"; }
            else if (name.matches("(?:docker-)?compose(?:[.-].*)?\\.ya?ml") || name.endsWith(".conf")) {
                id = "DEPLOYMENT_CONFIG"; label = "배포·서버 설정 후보 파일";
            } else if (name.matches(".*\\.(?:go|rs|rb|php|cs|kt|swift)")) { id = "OTHER_SOURCE"; label = "기타 언어 코드"; }
            if (id != null) add(groups, id, label, entry.status(), entry.filePath(),
                    "이 파일 영역은 검사하지 못했습니다. 파일 이름에 따른 범위 기록이며 실제 서버 역할이나 위험 여부를 확정하지 않습니다.");
        }
        for (var file : files) {
            if (file.type() == ProjectFileType.PYTHON_REQUIREMENTS || file.type() == ProjectFileType.PYTHON_PROJECT) {
                add(groups, "PYTHON_DEPENDENCIES", "Python 의존성 선언", "PARTIAL", file.relativePath(),
                        "지원하는 정적 선언만 SCA에서 확인합니다. 파일별 파싱·조회 상태를 함께 확인하세요. 실제 설치·환경 조건·간접 의존성 전체는 미검증이며 Python 인증·권한·데이터 흐름 분석은 지원하지 않습니다.");
            } else if (file.type() == ProjectFileType.PYTHON_LOCK) {
                add(groups, "PYTHON_DEPENDENCIES", "Python 의존성 형식", "UNSUPPORTED", file.relativePath(),
                        "이 형식은 아직 의존성을 추출하지 않습니다. SCA의 미지원 파일 기록을 확인하세요.");
            }
            if (file.type() == ProjectFileType.DOCKERFILE) {
                var runtime = DockerRuntimeUser.inspect(file);
                add(groups, "DOCKER_DEFAULT_STAGE", "Docker 기본 최종 stage", runtime.status().name(), file.relativePath(),
                        runtime.status() == DockerRuntimeUser.Status.UNKNOWN
                        ? "최종 실행 사용자를 확인하지 못했습니다. 기반 이미지의 USER 또는 동적 표현식 확인이 필요합니다. root나 안전으로 확정하지 않습니다."
                        : "Dockerfile의 기본 최종 stage 선언만 확인했습니다. 이미지 내부 사용자 UID, 별도 build target, Compose·실행 시 사용자 변경은 미검증입니다.");
            } else if (file.type() == ProjectFileType.GRADLE_BUILD) {
                add(groups, "GRADLE_DECLARATIONS", "Gradle 정적 선언", "PARTIAL", file.relativePath(),
                        "지원하는 정적 의존성 선언만 추출합니다. 플러그인·동적 빌드 로직·버전 카탈로그·실제 설치는 실행하거나 해석하지 않습니다.");
            }
        }
        var incomplete = ledger.analyzers().stream().filter(a -> !Set.of("COMPLETE", "NOT_APPLICABLE").contains(a.status()))
                .map(a -> a.analyzer() + ":" + a.status()).distinct().toList();
        return new InspectionScope(1, "NOT_ESTABLISHED", ledger.inventoryComplete() && ledger.omittedEntries() == 0,
                List.copyOf(groups.values()), incomplete);
    }

    private static void add(Map<String, Area> groups, String id, String label, String status, String path, String limitation) {
        String key = id + ":" + status;
        Area previous = groups.get(key);
        List<String> paths = new ArrayList<>(previous == null ? List.of() : previous.examplePaths());
        String safePath = CoverageRecorder.safePath(path);
        if (paths.size() < 3 && !paths.contains(safePath)) paths.add(safePath);
        groups.put(key, new Area(id, label, status, previous == null ? 1 : previous.observedFiles() + 1, List.copyOf(paths), limitation));
    }
}
