package com.securedeploy.ai.usage;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Map;
/** Reviewed public standard text-token rates, not an invoice or account availability check. */
public final class AiCostPolicy {
 private AiCostPolicy() { }
 public static final String SOURCE="https://developers.openai.com/api/docs/models/gpt-5.4-mini";
 public static final String CHECKED="2026-10-30";
 public static boolean priced(String model){return ("gpt-5.4-mini".equals(model)||"gpt-5.4-mini-2026-03-17".equals(model))&&!LocalDate.now(ZoneOffset.UTC).isAfter(LocalDate.parse(CHECKED).plusDays(30));}
 public static BigDecimal cost(AiTokenUsage u){
  if(!u.billable())return BigDecimal.ZERO;
  if(!u.usageKnown()||!priced(u.model())||u.promptTokens()<0||u.completionTokens()<0||u.cachedInputTokens()<0||u.cachedInputTokens()>u.promptTokens())return null;
  return new BigDecimal(u.promptTokens()-u.cachedInputTokens()).multiply(new BigDecimal("0.75")).add(new BigDecimal(u.cachedInputTokens()).multiply(new BigDecimal("0.075"))).add(new BigDecimal(u.completionTokens()).multiply(new BigDecimal("4.50"))).movePointLeft(6);
 }
 public static Map<String,Object> disclosure(String model){
  // UTF-8 byte budgets are deliberately conservative token bounds, including instructions/schema allowance.
  int input=32768,output=4000;
  var m=new java.util.LinkedHashMap<String,Object>();m.put("model",model);m.put("inputTokenUpperBound",input);m.put("outputTokenUpperBound",output);m.put("estimateKind","CONSERVATIVE_BOUND_NOT_TOKENIZER");m.put("pricingStatus",priced(model)?"KNOWN_STANDARD_TEXT_RATES":"UNKNOWN_OR_STALE");m.put("maximumEstimatedUsd",priced(model)?new BigDecimal(input).multiply(new BigDecimal("0.75")).add(new BigDecimal(output).multiply(new BigDecimal("4.50"))).movePointLeft(6):null);m.put("source",SOURCE);m.put("checkedAt",CHECKED);m.put("notices",java.util.List.of("단순 입력·출력 예산 기준 추정입니다. 실제 토큰과 청구액은 API 응답·계정 조건에 따라 달라집니다.","비밀값을 포함하면 전송에 동의하지 마세요. AI 결과는 검토가 필요한 제안입니다."));return m;
 }
}
