package com.securedeploy.ai.usage;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

/** Explicit consent context, never inherited by background threads. No prompt is persisted. */
public final class AiAdmission implements AutoCloseable {
    public record Request(long user,long project,String requestId,String feature,String consentHash,
                          String model,String transmissionHash) { }
    private static final ThreadLocal<Request> CURRENT=new ThreadLocal<>();
    private AiAdmission(Request r){if(CURRENT.get()!=null)throw new IllegalStateException("Nested AI admission");CURRENT.set(r);}
    public static AiAdmission open(long user,long project,String requestId,String feature,String consentHash,
                                  String model,String instructions,String data){
        return new AiAdmission(new Request(user,project,requestId,feature,consentHash,model,hash(instructions+"\0"+data)));
    }
    public static Request current(){return CURRENT.get();}
    public static String hash(String value){try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));}catch(Exception e){throw new IllegalStateException();}}
    @Override public void close(){CURRENT.remove();}
}
