package com.securedeploy.source;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import com.securedeploy.project.progress.*;
class SourceManifestTest {
 @TempDir Path temp;
 @Test void recordsExactBytesAndCanonicalRelativeRootWithoutRetainingContent()throws Exception{
  Path source=Files.createDirectories(temp.resolve("extracted/project/src"));Path file=source.resolve("api.js");byte[] bytes="export const ready=true;\r\n".getBytes(java.nio.charset.StandardCharsets.UTF_8);Files.write(file,bytes);Path zip=temp.resolve("project.zip");Files.write(zip,new byte[]{1,2,3});
  var evidence=new ComparisonEvidence(1,"SHA256_BYTES_V1",Map.of("src/api.js",SourceManifest.digest(bytes)),true,Map.of());
  var manifest=SourceManifest.capture(source.getParent().toRealPath(),zip,null,evidence,null);assertTrue(manifest.valid());assertTrue(manifest.complete());assertTrue(manifest.analyzedBytesConfirmed());assertEquals("project",manifest.rootPrefix());assertEquals(SourceManifest.digest(new byte[]{1,2,3}),manifest.archiveSha256());assertEquals(bytes.length,manifest.files().get(0).size());assertEquals("UTF8",manifest.files().get(0).encoding());
  var c=new ComparisonContext(1,null,"v53",true,List.of("src/api.js"),null,evidence,manifest);var converter=new ComparisonContextConverter();assertEquals(c,converter.convertToEntityAttribute(converter.convertToDatabaseColumn(c)));assertFalse(converter.convertToDatabaseColumn(c).contains("export const"));
 }
 @Test void changedAnalyzedBytesOrPartialHashCoverageCannotBeConfirmed()throws Exception{
  Path root=Files.createDirectory(temp.resolve("root"));Files.writeString(root.resolve("app.js"),"changed");var evidence=new ComparisonEvidence(1,"SHA256_BYTES_V1",Map.of("app.js",SourceManifest.digest("before".getBytes())),true,Map.of());var m=SourceManifest.capture(root,null,"a".repeat(40),evidence,null);assertFalse(m.analyzedBytesConfirmed());assertTrue(m.valid());assertFalse(SourceManifest.capture(root,null,"a".repeat(40),null,null).analyzedBytesConfirmed());
 }
 @Test void unsupportedSnapshotDoesNotInventSourceEvidence(){var c=new ComparisonContextConverter().convertToEntityAttribute("{\"schemaVersion\":1,\"ruleAnalysisComplete\":true,\"sourceManifest\":{\"version\":999}}");assertEquals(0,c.schemaVersion());assertNull(c.sourceManifest());}
 @Test void linksAndBinaryAreDistinguishedWithoutFollowingOutsideSource()throws Exception{
  Path root=Files.createDirectory(temp.resolve("root"));Files.write(root.resolve("data.bin"),new byte[]{0,-1,1});Files.createSymbolicLink(root.resolve("outside"),temp);var m=SourceManifest.capture(root,null,"a".repeat(40),new ComparisonEvidence(1,"SHA256_BYTES_V1",Map.of(),true,Map.of()),null);assertFalse(m.complete());assertEquals(1,m.files().size());assertEquals("BINARY_OR_UNVERIFIED_ENCODING",m.files().get(0).encoding());
 }
}
