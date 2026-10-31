package com.securedeploy.source;

import com.securedeploy.project.progress.ComparisonEvidence;
import com.securedeploy.project.coverage.CoverageLedger;
import java.nio.file.*;
import java.nio.charset.*;
import java.security.*;
import java.util.*;

/** Digests only. Uploaded source bytes are not retained in the Review. */
public record SourceManifest(int version,String kind,String archiveSha256,String commitSha,String rootPrefix,
        boolean complete,boolean analyzedBytesConfirmed,List<File> files) {
    public record File(String path,String sha256,long size,String encoding,boolean analyzed,String parseStatus) { }
    public SourceManifest { files=files==null?List.of():List.copyOf(files); }
    public static String digest(byte[] bytes){try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}catch(Exception e){throw new IllegalStateException(e);}}
    public static String digest(Path path)throws java.io.IOException {try {var d=MessageDigest.getInstance("SHA-256");try(var in=Files.newInputStream(path)){var b=new byte[65536];int n;while((n=in.read(b))!=-1)d.update(b,0,n);}return HexFormat.of().formatHex(d.digest());}catch(NoSuchAlgorithmException e){throw new IllegalStateException(e);}}
    public static SourceManifest capture(Path root,Path archive,String commit,ComparisonEvidence evidence,CoverageLedger coverage){return capture(root,archive,commit,evidence,coverage,null);}
    public static SourceManifest capture(Path root,Path archive,String commit,ComparisonEvidence evidence,CoverageLedger coverage,com.securedeploy.analysis.typescript.ServerAnalysisSnapshot server){
        var out=new ArrayList<File>();boolean complete=true,confirmed=evidence!=null&&evidence.complete();long total=0;
        try {
            var coverageIndex=new HashMap<String,TreeSet<String>>();
            if(coverage!=null)for(var e:coverage.entries())coverageIndex.computeIfAbsent(e.filePath(),ignored->new TreeSet<>()).add(e.status()+":"+e.reason());
            var parserIndex=new HashMap<String,TreeSet<String>>();
            if(server!=null)for(var a:java.util.stream.Stream.of(server,server.pythonAnalysis()).filter(Objects::nonNull).toList())for(var f:a.files())parserIndex.computeIfAbsent(f.filePath(),ignored->new TreeSet<>()).add(f.parseStatus()+":"+f.flowStatus());
            var inventory=inventory(root);complete=inventory.complete();
            for(var p:inventory.files()){String relative=root.relativize(p).toString().replace('\\','/');
                if(relative.isEmpty()||relative.equals(".git")||relative.startsWith(".git/"))continue;
                if(Files.isSymbolicLink(p)){complete=false;continue;}if(Files.isDirectory(p,LinkOption.NOFOLLOW_LINKS))continue;
                if(!Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)||relative.length()>512){complete=false;continue;}
                long size=Files.size(p);if(out.size()>=10000||size>100_000_000-total){complete=false;break;}total+=size;
                String hash=digest(p),encoding="BINARY_OR_UNVERIFIED_ENCODING";
                if(size<=256*1024){byte[] bytes=Files.readAllBytes(p);try{String text=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(bytes)).toString();if(text.chars().noneMatch(c->c<32&&c!='\r'&&c!='\n'&&c!='\t'))encoding=text.startsWith("\ufeff")?"UTF8_BOM":"UTF8";}catch(CharacterCodingException ignored){}finally{Arrays.fill(bytes,(byte)0);}}
                boolean analyzed=evidence!=null&&evidence.fileHashes().containsKey(relative);if(analyzed&&!hash.equals(evidence.fileHashes().get(relative)))confirmed=false;
                String parse=coverageIndex.containsKey(relative)?String.join(";",coverageIndex.get(relative)):"NOT_RECORDED";
                if(server!=null)parse=(parserIndex.containsKey(relative)?String.join(";",parserIndex.get(relative)):"PARSER_NOT_RECORDED")+";"+parse;
                out.add(new File(relative,hash,size,encoding,analyzed,parse.length()>256?parse.substring(0,256):parse));
            }
            if(evidence!=null&&!out.stream().filter(File::analyzed).map(File::path).collect(java.util.stream.Collectors.toSet()).containsAll(evidence.fileHashes().keySet()))confirmed=false;
            return new SourceManifest(1,archive==null?(commit==null?"WORKSPACE":"GITHUB"):"ZIP",archive==null?null:digest(archive),commit,archive==null?"":archive.getParent().toRealPath().resolve("extracted").toRealPath().relativize(root.toRealPath()).toString().replace('\\','/'),complete,confirmed,out.stream().sorted(Comparator.comparing(File::path)).toList());
        }catch(Exception unavailable){return new SourceManifest(1,archive==null?(commit==null?"WORKSPACE":"GITHUB"):"ZIP",null,commit,"",false,false,out);}
    }
    private record Inventory(List<Path> files,boolean complete) { }
    private static Inventory inventory(Path root)throws java.io.IOException {
        var files=new ArrayList<Path>();boolean[] complete={true};
        Files.walkFileTree(root,new SimpleFileVisitor<Path>(){
            @Override public FileVisitResult preVisitDirectory(Path dir,java.nio.file.attribute.BasicFileAttributes a){
                if(!dir.equals(root)&&dir.getFileName().toString().equals(".git"))return FileVisitResult.SKIP_SUBTREE;
                if(root.relativize(dir).getNameCount()>64){complete[0]=false;return FileVisitResult.SKIP_SUBTREE;}return FileVisitResult.CONTINUE;
            }
            @Override public FileVisitResult visitFile(Path file,java.nio.file.attribute.BasicFileAttributes a){if(files.size()>=10000){complete[0]=false;return FileVisitResult.TERMINATE;}files.add(file);return FileVisitResult.CONTINUE;}
            @Override public FileVisitResult visitFileFailed(Path file,java.io.IOException e){complete[0]=false;return FileVisitResult.CONTINUE;}
        });return new Inventory(files,complete[0]);
    }
    public boolean valid(){return version==1&&Set.of("ZIP","GITHUB","WORKSPACE").contains(kind)&&files.size()<=10000&&(archiveSha256==null||archiveSha256.matches("[a-f0-9]{64}"))&&(commitSha==null||commitSha.matches("[a-f0-9]{40}"))&&rootPrefix!=null&&safe(rootPrefix,true)&&files.stream().allMatch(f->f!=null&&safe(f.path(),false)&&f.sha256()!=null&&f.sha256().matches("[a-f0-9]{64}")&&f.size()>=0&&f.size()<=100_000_000&&f.encoding()!=null&&f.encoding().length()<64&&f.parseStatus()!=null&&f.parseStatus().length()<=256)&&files.stream().map(File::path).distinct().count()==files.size();}
    private static boolean safe(String p,boolean empty){return p!=null&&(empty||!p.isEmpty())&&p.length()<=512&&!p.startsWith("/")&&!p.contains("\\")&&!p.contains(":")&&Arrays.stream(p.split("/",-1)).noneMatch(s->s.equals("..")||s.equals(".")||s.isEmpty()&&!p.isEmpty());}
}
