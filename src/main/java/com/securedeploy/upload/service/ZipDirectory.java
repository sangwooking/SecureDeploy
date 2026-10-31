package com.securedeploy.upload.service;

import java.io.*;
import java.nio.file.Path;
/** Bounded central-directory scan before Commons Compress may allocate entry objects. */
public final class ZipDirectory {
 private ZipDirectory() { }
 private interface Reader {long size()throws IOException;byte[] read(long at,int count)throws IOException;}
 public static int validate(Path path,int maximum)throws IOException {try(var f=new RandomAccessFile(path.toFile(),"r")){return validate(new Reader(){public long size()throws IOException{return f.length();}public byte[] read(long at,int n)throws IOException{if(at<0||at>f.length()-n)throw new EOFException();byte[] b=new byte[n];f.seek(at);f.readFully(b);return b;}},maximum);}}
 public static int validate(byte[] bytes,int maximum)throws IOException{return validate(new Reader(){public long size(){return bytes.length;}public byte[] read(long at,int n)throws IOException{if(at<0||at>bytes.length-n)throw new EOFException();return java.util.Arrays.copyOfRange(bytes,(int)at,(int)at+n);}},maximum);}
 private static int validate(Reader reader,int maximum)throws IOException {
  long length=reader.size(),tailStart=Math.max(0,length-65557);byte[] tail=reader.read(tailStart,(int)(length-tailStart));int end=-1;
  for(int i=tail.length-22;i>=0;i--)if(le(tail,i,4)==0x06054b50L&&i+22+le(tail,i+20,2)==tail.length){end=i;break;}
  if(end<0||le(tail,end+4,2)!=0||le(tail,end+6,2)!=0||le(tail,end+8,2)!=le(tail,end+10,2)||le(tail,end+12,4)==0xffffffffL||le(tail,end+16,4)==0xffffffffL)throw new IOException("Unsupported ZIP directory");
  long expected=le(tail,end+10,2),size=le(tail,end+12,4),position=le(tail,end+16,4),limit=tailStart+end;
  if(expected>maximum)throw new TooManyEntries();if(expected==0||position+size!=limit||position<0)throw new IOException("Invalid ZIP directory bounds");
  int count=0;while(position<limit){if(++count>maximum)throw new TooManyEntries();if(limit-position<46)throw new IOException("Truncated ZIP directory");byte[] h=reader.read(position,46);if(le(h,0,4)!=0x02014b50L||le(h,34,2)!=0||le(h,42,4)>=le(tail,end+16,4))throw new IOException("Invalid ZIP entry directory");long next=position+46+le(h,28,2)+le(h,30,2)+le(h,32,2);if(next>limit||next<=position)throw new IOException("Invalid ZIP entry bounds");position=next;}
  if(count!=expected)throw new IOException("ZIP directory count mismatch");return count;
 }
 private static long le(byte[] b,int p,int n){long out=0;for(int i=0;i<n;i++)out|=(long)(b[p+i]&255)<<(8*i);return out;}
 public static final class TooManyEntries extends IOException { }
}
