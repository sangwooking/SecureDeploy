package com.securedeploy.ai.remediation;

import com.securedeploy.ai.dto.AiConfidence;
import java.util.List;

/** Advice only: no fields capable of changing the deterministic risk assessment. */
public record RemediationContent(String summary, String whyItMatters, String recommendedAction,
                                 String codeExample, String configurationExample,
                                 List<String> verificationSteps, String caution,
                                 AiConfidence remediationConfidence) { }
