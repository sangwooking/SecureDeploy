package com.securedeploy.ai.usage;
public record AiTokenUsage(int promptTokens,int completionTokens,int totalTokens,boolean billable,int cachedInputTokens,String model,boolean usageKnown) {
 public AiTokenUsage(int promptTokens,int completionTokens,int totalTokens,boolean billable){this(promptTokens,completionTokens,totalTokens,billable,0,null,totalTokens>0||!billable);}
}
