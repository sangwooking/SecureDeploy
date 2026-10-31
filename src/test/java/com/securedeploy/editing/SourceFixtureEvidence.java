package com.securedeploy.editing;
import com.securedeploy.persistence.entity.ReviewEntity;
import com.securedeploy.source.SourceManifest;
import com.securedeploy.project.progress.*;
import java.util.*;
/** Explicit expected bytes for controlled transport mocks, not a live GitHub proof. */
final class SourceFixtureEvidence {
 static List<SourceArchive.Entry> mark(ReviewEntity review,List<SourceArchive.Entry> entries){
  String commit=review.getSourceMetadata().commitSha();var hashes=new TreeMap<String,String>();var files=new ArrayList<SourceManifest.File>();for(var e:entries)if(!e.directory()){String hash=SourceArchive.hash(e.bytes());hashes.put(e.path(),hash);files.add(new SourceManifest.File(e.path(),hash,e.bytes().length,"FIXTURE_BYTES",true,"FIXTURE_ANALYSIS"));}
  var context=new ComparisonContext(1,null,"fixture",true,new ArrayList<>(hashes.keySet()),null,new ComparisonEvidence(1,"SHA256_BYTES_V1",hashes,true,Map.of()),new SourceManifest(1,"GITHUB",null,commit,"",true,true,files));
  if(org.mockito.Mockito.mockingDetails(review).isMock())org.mockito.Mockito.doReturn(context).when(review).getComparisonContext();else review.attachComparisonContext(context);return entries;
 }
}
