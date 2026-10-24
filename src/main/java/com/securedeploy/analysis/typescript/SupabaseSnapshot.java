package com.securedeploy.analysis.typescript;

import java.util.*;
import com.securedeploy.project.coverage.CoverageLedger;
import com.securedeploy.analysis.typescript.ServerAnalysisSnapshot.Location;

/** Repository declarations and call sites, never live database authorization. */
public record SupabaseSnapshot(int schemaVersion,String analyzerVersion,String status,List<SqlFile> files,
        List<Table> tables,List<Client> clients,List<Access> accesses,List<Finding> findings,List<String> limitations,Map<String,Integer> budgetUsage) {
    public SupabaseSnapshot(int schemaVersion,String analyzerVersion,String status,List<SqlFile> files,
            List<Table> tables,List<Client> clients,List<Access> accesses,List<Finding> findings,List<String> limitations) {
        this(schemaVersion,analyzerVersion,status,files,tables,clients,accesses,findings,limitations,null);
    }
    public record SqlFile(String filePath,String status,int statements,List<String> limitations) { }
    public record Condition(String kind,List<String> columns) { }
    public record Policy(String name,String command,String mode,List<String> roles,Condition using,Condition check,Location location) { }
    public record Operation(String role,String operation,String grant,String using,String check,List<String> columns,
            String state,boolean candidate,List<Location> policyLocations) { }
    public record Table(String scope,String table,String rls,String force,Location location,List<Location> grantLocations,List<Policy> policies,
            List<Operation> operations,List<String> limitations) { }
    public record Client(Location location,String keySource,String authContext,List<String> limitations) { }
    public record Access(Location location,String table,String operation,String clientStatus,Location clientLocation,
            String keySource,String policyStatus,Location policyLocation,List<String> limitations,AuthorizationEvidence authorizationEvidence) {
        public Access(Location location,String table,String operation,String clientStatus,Location clientLocation,
                String keySource,String policyStatus,Location policyLocation,List<String> limitations) {
            this(location,table,operation,clientStatus,clientLocation,keySource,policyStatus,policyLocation,limitations,null);
        }
    }
    public record AuthResultEvidence(String status,Location guardLocation,List<Location> userIdFilters,List<String> limitations) { }
    public record AuthCheck(String method,String status,Location location,AuthResultEvidence resultEvidence) {
        public AuthCheck(String method,String status,Location location){this(method,status,location,null);}
    }
    public record AuthorizationEvidence(String state,String clientContract,String authStatus,String effectiveRole,String roleEvidence,
            List<AuthCheck> authChecks,List<Location> clientTrace,List<Location> policyLocations,List<Location> filterLocations,
            Location enclosingFunction,List<String> policyStates,List<String> limitations,Location requestEntry) {
        public AuthorizationEvidence(String state,String clientContract,String authStatus,String effectiveRole,String roleEvidence,
                List<AuthCheck> authChecks,List<Location> clientTrace,List<Location> policyLocations,List<Location> filterLocations,
                Location enclosingFunction,List<String> policyStates,List<String> limitations){
            this(state,clientContract,authStatus,effectiveRole,roleEvidence,authChecks,clientTrace,policyLocations,filterLocations,enclosingFunction,policyStates,limitations,null);
        }
    }
    public record Finding(String findingId,String ruleId,String priority,String comparisonPolicy,String table,Location location,
            List<String> roles,List<String> operations,List<Location> evidenceLocations,String title,String reason,
            String recommendation,List<String> verificationSteps,List<String> limitations) { }
    public CoverageLedger attachCoverage(CoverageLedger ledger) {
        var counts=new TreeMap<String,Integer>();
        files.forEach(f->counts.merge("SQL_"+f.status(),1,Integer::sum));
        counts.put("TABLE_DECLARATIONS",tables.size());counts.put("CLIENT_DECLARATIONS",clients.size());
        counts.put("DATA_ACCESS_DECLARATIONS",accesses.size());counts.put("REVIEW_CANDIDATES",findings.size());
        var authSites=new HashSet<Location>();var guards=new HashSet<Location>();var identityFilters=new HashSet<Location>();
        accesses.forEach(a->{
            var evidence=a.authorizationEvidence();
            counts.merge("ACCESS_AUTH_"+(evidence==null?"UNRECORDED":evidence.state()),1,Integer::sum);
            if(evidence!=null){
                counts.merge("AUTH_CHECK_REFERENCES",evidence.authChecks().size(),Integer::sum);
                if(evidence.requestEntry()!=null)counts.merge("NEXT_ACCESS_ENTRY_DECLARATIONS",1,Integer::sum);
                for(var check:evidence.authChecks()){
                    authSites.add(check.location());
                    if(check.resultEvidence()!=null){guards.add(check.resultEvidence().guardLocation());identityFilters.addAll(check.resultEvidence().userIdFilters());}
                }
            }
        });
        counts.put("AUTH_API_CALLS_OBSERVED",authSites.size());
        counts.put("AUTH_RESULT_GUARDS_OBSERVED",guards.size());counts.put("IDENTITY_ID_FILTERS_OBSERVED",identityFilters.size());
        if(budgetUsage!=null)counts.putAll(budgetUsage);
        var analyzers=new ArrayList<>(ledger.analyzers());
        analyzers.add(new CoverageLedger.Analyzer("SUPABASE_RLS",status,
                "SQL migration 선언과 제한된 Client 사용 위치를 확인합니다. 실제 DB 적용·사용자 인증·권한 상속·RLS 우회는 미검증이며 기존 점수·Risk와 분리됩니다.",counts));
        return new CoverageLedger(ledger.schemaVersion(),ledger.policyVersion(),
                "FAILED".equals(ledger.status())?"FAILED":"NOT_APPLICABLE".equals(status)?ledger.status():"PARTIAL",
                ledger.discoveredFiles(),ledger.selectedFiles(),ledger.unsupportedFiles(),ledger.excludedFiles(),ledger.failedFiles(),
                ledger.inventoryComplete(),ledger.omittedEntries(),ledger.entries(),List.copyOf(analyzers),ledger.inspectionScope());
    }
}
