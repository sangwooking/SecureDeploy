package com.securedeploy.analysis.typescript;

import com.securedeploy.project.model.*;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

class NextServerFlowTest {
    final TypeScriptServerAnalyzer analyzer = new TypeScriptServerAnalyzer(new TypeScriptAnalysisProperties());

    ProjectStructure project(String path, String code) {
        Path root = Path.of("/not-readable-next-target");
        return new ProjectStructure(root, List.of(
                new ProjectFile(root.resolve("package.json"), "package.json", ProjectFileType.PACKAGE_JSON,
                        List.of("{\"dependencies\":{\"next\":\"15.3.0\"}}")),
                new ProjectFile(root.resolve(path), path, ProjectFileType.TYPESCRIPT, code.lines().toList())));
    }

    @Test void requestToResponseBecomesReviewOnlyFindingAndRoundTripsWithoutSource() {
        var result = analyzer.analyze(project("src/app/api/check/route.ts", """
                import {NextResponse} from 'next/server';
                export async function POST(request: Request) {
                  const body = await request.json();
                  await fetch(body.destination);
                  return NextResponse.json({value: process.env.SYNTHETIC_PRIVATE_KEY_NAME});
                }
                """));
        assertThat(result.authorizationContexts()).hasSize(1);
        assertThat(result.authorizationContexts().get(0).entry().kind()).isEqualTo("NEXT_ROUTE_HANDLER");
        assertThat(result.validatedFindings()).extracting(ServerFlowFinding::ruleId)
                .containsExactlyInAnyOrder("TS_SSRF_INPUT_FLOW", "TS_SENSITIVE_DATA_EXPOSURE");
        assertThat(result.validatedFindings()).allSatisfy(f -> {
            assertThat(f.priority().name()).isEqualTo("REVIEW_REQUIRED");
            assertThat(f.comparisonPolicy()).isEqualTo("NOT_COMPARED");
        });
        var converter = new ServerAnalysisConverter();
        String json = converter.convertToDatabaseColumn(result);
        assertThat(json).doesNotContain("SYNTHETIC_PRIVATE_KEY_NAME", "process.env", "NextResponse.json");
        assertThat(converter.convertToEntityAttribute(json)).isEqualTo(result);
    }

    @Test void serverReturnIsEvidenceNotProofOfClientInvocationOrAuthorization() {
        var result = analyzer.analyze(project("app/actions.ts", """
                'use server';
                export async function inspect(data:FormData) {return {value:process.env.API_KEY};}
                """));
        assertThat(result.validatedFindings()).hasSize(1);
        assertThat(result.validatedFindings().get(0).location().kind()).isEqualTo("SERVER_FUNCTION_RETURN");
        assertThat(result.files().get(0).limitations()).contains("NEXT_SERVER_FUNCTION_INVOCATION_NOT_VERIFIED");
        assertThat(result.authorizationContexts().get(0).conclusion()).isEqualTo("NOT_VERIFIED");
        assertThat(analyzer.analyze(project("app/api/check/route.ts", """
                export async function GET(){useKey(process.env.API_KEY);return Response.json({ok:true});}
                """)).validatedFindings()).isEmpty();
    }
}
