package com.securedeploy.upload.service;

import java.io.*;
import java.nio.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.text.Normalizer;
import java.util.*;
import org.apache.commons.compress.archivers.zip.ZipFile;

/** Validate central-directory identity before materializing any archive file. */
final class ZipMetadata {
    static Set<String> inspect(Path file,int maxEntries)throws IOException {
        int expected;
        try{expected=ZipDirectory.validate(file,maxEntries);}catch(ZipDirectory.TooManyEntries many){throw new EntryLimit();}
        var names=new HashSet<String>();var folded=new HashMap<String,Boolean>();
        try(var zip=ZipFile.builder().setPath(file).get()){
            var entries=zip.getEntries();while(entries.hasMoreElements()){
                var e=entries.nextElement();if(names.size()>=maxEntries)throw new EntryLimit();
                String name=e.getName();if(e.getGeneralPurposeBit().usesUTF8ForNames()){
                    String raw=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(e.getRawName())).toString();if(!raw.equals(name))throw new IOException("Conflicting ZIP path encoding");
                }
                if(name.indexOf('\ufffd')>=0)throw new IOException("Undecodable ZIP name");
                int type=e.getUnixMode()&0170000;
                if(e.isUnixSymlink()||(type!=0&&type!=0100000&&type!=0040000)||e.getGeneralPurposeBit().usesEncryption()||!zip.canReadEntryData(e)||(e.getMethod()!=0&&e.getMethod()!=8))throw new IOException("Unsupported ZIP object");
                String key=key(name,e.isDirectory());if(!names.add(name)||folded.putIfAbsent(key,e.isDirectory())!=null)throw new IOException("ZIP path collision");
            }
        }
        if(names.size()!=expected)throw new IOException("ZIP count mismatch");
        for(String p:folded.keySet())for(int slash=p.indexOf('/');slash>=0;slash=p.indexOf('/',slash+1))if(Boolean.FALSE.equals(folded.get(p.substring(0,slash))))throw new IOException("ZIP parent is a file");
        return names;
    }
    private static String key(String raw,boolean directory)throws IOException {
        String name=directory&&raw.endsWith("/")?raw.substring(0,raw.length()-1):raw;
        while(name.startsWith("./"))name=name.substring(2);
        if(directory&&(name.equals(".")||name.isEmpty()))return "";
        if(name.length()>512||name.startsWith("/")||name.contains("\\")||name.contains(":"))throw new IOException("Unsafe ZIP path");
        var parts=name.split("/",-1);if(parts.length>64)throw new IOException("ZIP depth limit");
        for(String p:parts)if(p.isEmpty()||p.equals("..")||p.equals(".")||p.endsWith(".")||p.endsWith(" ")||p.chars().anyMatch(c->c<32||c==127)||p.matches("(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\\..*)?"))throw new IOException("Unsafe ZIP path");
        return Normalizer.normalize(name,Normalizer.Form.NFC).toLowerCase(Locale.ROOT);
    }
    private static long le(byte[] b,int p,int n){long out=0;for(int i=0;i<n;i++)out|=(long)(b[p+i]&255)<<(8*i);return out;}
    static final class EntryLimit extends IOException { }
}
