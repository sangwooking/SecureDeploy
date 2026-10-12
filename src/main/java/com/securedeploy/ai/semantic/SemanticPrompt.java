package com.securedeploy.ai.semantic;

public record SemanticPrompt(String instructions, String untrustedData, int maxOutputTokens) { }
