package com.securedeploy.sca.client;

import com.securedeploy.sca.model.DependencyVulnerability;
import java.util.*;

/** Alias identity is not package identity. Conflicting risk/fix metadata is never discarded. */
final class OsvAliasDeduplicator {
    private OsvAliasDeduplicator() { }
    static List<DependencyVulnerability> merge(List<DependencyVulnerability> input,List<String> warnings) {
        var components=new LinkedHashMap<String,List<DependencyVulnerability>>();
        for(var f:input)components.computeIfAbsent(f.ecosystem()+"|"+f.packageName()+"|"+f.installedVersion(),k->new ArrayList<>()).add(f);
        var result=new ArrayList<DependencyVulnerability>();int comparisons=0;boolean conflict=false,budget=false;
        for(var group:components.values()) {
            var aliasSets=group.stream().map(OsvAliasDeduplicator::aliases).toList();
            int[] parents=new int[group.size()];for(int i=0;i<parents.length;i++)parents[i]=i;
            for(int i=0;i<group.size();i++)for(int j=i+1;j<group.size();j++) {
                if(++comparisons>50_000){budget=true;break;}
                var a=group.get(i);var b=group.get(j);
                if(!sameIdentity(a,b,aliasSets.get(i),aliasSets.get(j)))continue;
                if(a.severity()!=b.severity()||!Objects.equals(a.cvssScore(),b.cvssScore())
                        ||!new HashSet<>(a.fixedVersions()).equals(new HashSet<>(b.fixedVersions()))
                        ||!Objects.equals(a.affectedRanges()==null?null:new HashSet<>(a.affectedRanges()),b.affectedRanges()==null?null:new HashSet<>(b.affectedRanges()))) {conflict=true;continue;}
                parents[root(parents,j)]=root(parents,i);
            }
            var clusters=new LinkedHashMap<Integer,List<DependencyVulnerability>>();
            for(int i=0;i<group.size();i++)clusters.computeIfAbsent(root(parents,i),k->new ArrayList<>()).add(group.get(i));
            for(var cluster:clusters.values())result.add(combine(cluster));
        }
        if(conflict)warnings.add("같은 패키지의 advisory 별칭은 연결되지만 심각도·영향 범위·수정 버전 근거가 달라 별도로 보존했습니다. 중복과 수정 가능성을 추가 확인하세요.");
        if(budget)warnings.add("Advisory 별칭 비교 한도로 일부 중복을 확인하지 못했습니다. 기존 결과를 보존했습니다.");
        return List.copyOf(result);
    }
    private static int root(int[] parents,int i){while(parents[i]!=i){parents[i]=parents[parents[i]];i=parents[i];}return i;}
    private static boolean sameIdentity(DependencyVulnerability a,DependencyVulnerability b,Set<String> left,Set<String> right) {
        return left.contains(b.osvId())&&right.contains(a.osvId())||left.stream().anyMatch(right::contains);
    }
    private static Set<String> aliases(DependencyVulnerability f) {
        var values=new HashSet<String>();if(f.aliases()!=null)for(String a:f.aliases().stream().limit(200).toList())if(a!=null&&a.matches("[A-Za-z0-9][A-Za-z0-9_.-]{0,199}"))values.add(a);return values;
    }
    private static DependencyVulnerability combine(List<DependencyVulnerability> group) {
        if(group.size()==1)return group.get(0);
        group.sort(Comparator.comparingInt((DependencyVulnerability f)->f.osvId().startsWith("GHSA-")?0:1).thenComparing(DependencyVulnerability::osvId));
        var f=group.get(0);var aliases=new TreeSet<String>();var paths=new TreeSet<String>();var refs=new TreeSet<String>();var vectors=new TreeSet<String>();
        for(var row:group){aliases.add(row.osvId());aliases.addAll(row.aliases());paths.addAll(row.sourceFiles());refs.addAll(row.referenceUrls());vectors.addAll(row.cvssVectors());}
        aliases.remove(f.osvId());
        return new DependencyVulnerability(f.ecosystem(),f.packageName(),f.installedVersion(),f.osvId(),List.copyOf(aliases),f.summary(),f.severity(),f.cvssScore(),List.copyOf(vectors),
                f.fixedVersions(),f.published(),f.modified(),List.copyOf(refs),List.copyOf(paths),f.affectedRanges());
    }
}
