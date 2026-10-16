package com.securedeploy.sca.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record SupplementalDependencyRequest(
        @NotBlank(message = "확인할 분석 항목을 선택해 주세요.") @Size(max = 1024) String findingId,
        @NotBlank(message = "라이브러리 이름을 입력해 주세요.") @Size(max = 256, message = "라이브러리 이름은 256자 이내로 입력해 주세요.") String packageName,
        @NotBlank(message = "현재 사용 버전을 입력해 주세요.") @Size(max = 128, message = "버전은 128자 이내로 입력해 주세요.") String version
) { }
