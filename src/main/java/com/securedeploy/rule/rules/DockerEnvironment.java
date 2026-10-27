package com.securedeploy.rule.rules;

import com.securedeploy.project.model.ProjectFile;
import java.util.*;
import java.util.regex.Pattern;

/** Bounded ENV syntax, not shell execution, image inspection or a complete Dockerfile parser. */
public final class DockerEnvironment {
    public record Declaration(int line,String kind) { }
    public record Analysis(boolean complete,List<Declaration> declarations,List<Declaration> traits) { }
    private record Word(String value,int offset) { }
    private record Segment(int offset,int line) { }
    private static final Pattern SECRET=Pattern.compile("(?i).*(PASSWORD|TOKEN|SECRET|API_KEY|PRIVATE_KEY).*");
    private DockerEnvironment() { }
    public static Analysis inspect(ProjectFile file) {
        var declarations=new ArrayList<Declaration>();var traits=new ArrayList<Declaration>();
        if(file.lines().stream().mapToLong(s->s.length()+1L).sum()>100_000)return new Analysis(false,List.of(),List.of());
        long deadline=System.nanoTime()+100_000_000L;var logical=new StringBuilder();var segments=new ArrayList<Segment>();int start=1;boolean stage=false;
        try {
            for(int i=0;i<file.lines().size();i++) {
                if(System.nanoTime()>deadline||declarations.size()+traits.size()>500)throw new IllegalArgumentException();
                String line=file.lines().get(i).strip();
                if(line.matches("(?i)#\\s*escape\\s*=\\s*`"))throw new IllegalArgumentException();
                if(line.isEmpty()||line.startsWith("#"))continue;
                if(logical.isEmpty())start=i+1;
                boolean continued=line.endsWith("\\");segments.add(new Segment(logical.length(),i+1));logical.append(continued?line.substring(0,line.length()-1):line).append(' ');
                if(continued)continue;
                String instruction=logical.toString().strip();logical.setLength(0);
                String[] pair=instruction.split("\\s+",2);String op=pair[0].toUpperCase(Locale.ROOT),value=pair.length>1?pair[1]:"";
                if(op.equals("FROM"))stage=true;
                if(Set.of("RUN","COPY").contains(op)&&value.contains("<<"))throw new IllegalArgumentException();
                if(op.equals("ENV")) {
                    if(!stage)throw new IllegalArgumentException();
                    var words=words(value);if(words.isEmpty())throw new IllegalArgumentException();int valueStart=instruction.indexOf(value,pair[0].length());
                    if(!words.get(0).value.contains("=")) {
                        if(words.size()<2)throw new IllegalArgumentException();
                        declaration(words.get(0).value,String.join(" ",words.subList(1,words.size()).stream().map(Word::value).toList()),position(segments,valueStart+words.get(0).offset),declarations);
                    }else for(Word token:words){if(System.nanoTime()>deadline)throw new IllegalArgumentException();String word=token.value;int eq=word.indexOf('=');if(eq<1)throw new IllegalArgumentException();declaration(word.substring(0,eq),word.substring(eq+1),position(segments,valueStart+token.offset),declarations);}
                }else if(op.equals("RUN")&&value.matches("--mount=type=secret(?:,[^\\s]+)*\\s+.+"))traits.add(new Declaration(start,"build_secret_mount"));
                else if(op.equals("EXPOSE"))traits.add(new Declaration(start,"expose_declaration"));
                else if(op.equals("ARG"))traits.add(new Declaration(start,"build_arg_not_runtime_secret_proof"));
                else if(op.equals("COPY")||op.equals("ADD"))traits.add(new Declaration(start,"copy_context_and_dockerignore_unknown"));
                else if(op.equals("FROM"))traits.add(new Declaration(start,value.matches(".*@sha256:[a-fA-F0-9]{64}(?:\\s+[aA][sS]\\s+[^\\s]+)?")?"image_digest_declaration":"image_reference_not_contents"));
                if(declarations.size()+traits.size()>199)throw new IllegalArgumentException();
                segments.clear();
            }
            if(!logical.isEmpty())throw new IllegalArgumentException();
            return new Analysis(true,List.copyOf(declarations),List.copyOf(traits));
        }catch(IllegalArgumentException unsupported){var kept=declarations.stream().limit(199).toList();return new Analysis(false,kept,traits.stream().limit(199-kept.size()).toList());}
    }
    private static void declaration(String key,String value,int line,List<Declaration> declarations) {
        if(declarations.size()>=200)throw new IllegalArgumentException();
        if(!key.matches("[A-Za-z_][A-Za-z_0-9]*"))throw new IllegalArgumentException();
        if(SECRET.matcher(key).matches())declarations.add(new Declaration(line,value.isEmpty()?"EMPTY":value.contains("$")||value.contains("`")?"DYNAMIC":"LITERAL"));
    }
    private static int position(List<Segment> segments,int offset){int low=0,high=segments.size()-1;while(low<high){int mid=(low+high+1)/2;if(segments.get(mid).offset<=offset)low=mid;else high=mid-1;}return segments.get(low).line;}
    private static List<Word> words(String source) {
        var result=new ArrayList<Word>();var word=new StringBuilder();char quote=0;boolean escaped=false,present=false;int start=0;
        for(int index=0;index<source.length();index++) {char c=source.charAt(index);if(!present&&!Character.isWhitespace(c))start=index;
            if(escaped){word.append(c);escaped=false;present=true;continue;}
            if(c=='\\'){escaped=true;present=true;continue;}
            if(quote!=0){if(c==quote)quote=0;else word.append(c);present=true;continue;}
            if(c=='\''||c=='"'){quote=c;present=true;continue;}
            if(Character.isWhitespace(c)){if(present){result.add(new Word(word.toString(),start));word.setLength(0);present=false;}}
            else {word.append(c);present=true;}
        }
        if(escaped||quote!=0)throw new IllegalArgumentException();if(present)result.add(new Word(word.toString(),start));return result;
    }
}
