package com.securedeploy.editing;
import java.time.Instant;
/** Server-authored event. Proposal generation and explicit user approval are separate facts. No code or secrets. */
public record ChangeAttribution(long revision,String generator,String providerOrigin,String model,String proposalId,
        String directionOrigin,String adviceId,boolean approved,long userId,Instant at,String currentHash) { }
