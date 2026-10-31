package com.securedeploy.editing;
import com.securedeploy.persistence.entity.ReviewEntity;
import com.securedeploy.project.progress.*;
import com.securedeploy.source.SourceManifest;
import java.util.*;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
class SourceVerificationTest {
 ReviewEntity review=mock(ReviewEntity.class);byte[] bytes="ready\n".getBytes();String archive="a".repeat(64);List<SourceArchive.Entry> entries=List.of(new SourceArchive.Entry("src/health.js",bytes,false,0100644));
 void manifest(boolean complete,boolean confirmed){var m=new SourceManifest(1,"ZIP",archive,null,"bundle",complete,confirmed,List.of(new SourceManifest.File("src/health.js",SourceArchive.hash(bytes),bytes.length,"UTF8",true,"PARSED")));when(review.getComparisonContext()).thenReturn(new ComparisonContext(1,null,"engine",true,List.of("src/health.js"),null,null,m));}
 @Test void exactArchiveAndFileBytesAreBothRequired(){manifest(true,true);assertEquals("VERIFIED",SourceVerification.verify(review,entries,archive).status());assertEquals("MISMATCH",SourceVerification.verify(review,entries,"b".repeat(64)).status());assertEquals("MISMATCH",SourceVerification.verify(review,List.of(),archive).status());assertEquals("MISMATCH",SourceVerification.verify(review,List.of(new SourceArchive.Entry("src/health.js","other".getBytes(),false,0100644)),archive).status());}
 @Test void legacyAndPartialNeverBecomeVerified(){assertEquals("UNVERIFIED",SourceVerification.verify(review,entries,archive).status());manifest(false,true);assertEquals("PARTIAL",SourceVerification.verify(review,entries,archive).status());manifest(true,false);assertEquals("PARTIAL",SourceVerification.verify(review,entries,archive).status());}
 @Test void missingOrMovedFileNeverConnectsByBasename(){manifest(true,true);assertEquals("MISMATCH",SourceVerification.verify(review,List.of(new SourceArchive.Entry("other/health.js",bytes,false,0100644)),archive).status());}
 @Test void absentArchiveDigestAndEmptyEvidenceAreUnverifiedRatherThanInventedMismatch(){manifest(true,true);var c=review.getComparisonContext();var m=c.sourceManifest();when(review.getComparisonContext()).thenReturn(c.withSourceManifest(new SourceManifest(1,"ZIP",null,null,"",true,true,m.files())));assertEquals("PARTIAL",SourceVerification.verify(review,entries,archive).status());when(review.getComparisonContext()).thenReturn(c.withSourceManifest(new SourceManifest(1,"ZIP",archive,null,"",true,true,List.of())));assertEquals("UNVERIFIED",SourceVerification.verify(review,entries,archive).status());}

 @Test void repackedZipCanMatchFilesButMustNotBecomeVerifiedArchive(){manifest(true,true);var v=SourceVerification.verify(review,entries,"b".repeat(64));assertEquals("MISMATCH",v.status());assertEquals("FILE_MANIFEST_MATCH_ARCHIVE_MISMATCH",v.scope());assertTrue(v.message().contains("새 검사"));}
 @Test void extraFileOrPartialProofCannotClaimRepackedManifestEquality(){manifest(true,true);var extra=new ArrayList<>(entries);extra.add(new SourceArchive.Entry("extra.js",bytes,false,0100644));assertNotEquals("FILE_MANIFEST_MATCH_ARCHIVE_MISMATCH",SourceVerification.verify(review,extra,"b".repeat(64)).scope());assertEquals("MISMATCH",SourceVerification.verify(review,extra,archive).status());manifest(false,true);assertNotEquals("FILE_MANIFEST_MATCH_ARCHIVE_MISMATCH",SourceVerification.verify(review,entries,"b".repeat(64)).scope());}
}
