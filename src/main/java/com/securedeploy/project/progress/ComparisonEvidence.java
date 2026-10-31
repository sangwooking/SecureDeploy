package com.securedeploy.project.progress;
import java.util.*;
/** Bounded input digests and actual runtime identities. No source or secret bytes. */
public record ComparisonEvidence(int version,String hashAlgorithm,Map<String,String> fileHashes,
        boolean complete,Map<String,String> engines,Map<String,String> anchorHashes) {
 public ComparisonEvidence(int version,String algorithm,Map<String,String> hashes,boolean complete,Map<String,String> engines){this(version,algorithm,hashes,complete,engines,Map.of());}
 public ComparisonEvidence { anchorHashes=anchorHashes==null?Map.of():Map.copyOf(anchorHashes); fileHashes=fileHashes==null?Map.of():Map.copyOf(fileHashes);engines=engines==null?Map.of():Map.copyOf(engines); }
}
