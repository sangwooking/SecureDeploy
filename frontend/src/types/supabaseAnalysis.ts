import type { AnalysisLocation } from './serverAnalysis';
export interface SupabaseWriteValue {
  name:string;operator:string;location:AnalysisLocation;
  source:'REQUEST_CONTROLLED'|'VERIFIED_USER_EVIDENCE'|'SESSION_UNVERIFIED'|'SERVER_CONTROLLED'|'UNKNOWN';
  sourceLocations:AnalysisLocation[];limitations:string[];
}
export interface SupabaseAnalysis {
  schemaVersion:number;analyzerVersion:string;status:string;limitations:string[];
  budgetUsage?:Record<string,number>|null;
  files:{filePath:string;status:string;statements:number;limitations:string[]}[];
  tables:{scope:string;table:string;rls:string;force:string;location:AnalysisLocation;grantLocations:AnalysisLocation[];limitations:string[];
    policies:{name:string;command:string;mode:string;roles:string[];using:{kind:string;columns:string[]};check:{kind:string;columns:string[]};location:AnalysisLocation}[];
    operations:{role:string;operation:string;grant:string;using:string;check:string;columns:string[];state:string;candidate:boolean;policyLocations:AnalysisLocation[]}[];
    updatePrivileges?:{role:string;status:string;tableGrant:string;columns:string[]}[]|null;}[];
  clients:{location:AnalysisLocation;keySource:string;authContext:string;limitations:string[]}[];
  accesses:{location:AnalysisLocation;table:string;operation:string;clientStatus:string;clientLocation:AnalysisLocation|null;
    keySource:string;policyStatus:string;policyLocation:AnalysisLocation|null;limitations:string[];
    writeEvidence?:{status:string;operationLocation:AnalysisLocation;dataStatus:string;dataFields:SupabaseWriteValue[];filterStatus:string;filters:SupabaseWriteValue[];limitations:string[];
      columnUpdate?:{analyzerVersion:string;status:string;roles:{role:string;tableGrant:string;fields:{name:string;source:string;grant:string}[]}[];grantLocations:AnalysisLocation[];limitations:string[]}|null;}|null;
    authorizationEvidence?:{state:string;clientContract:string;authStatus:string;effectiveRole:string;roleEvidence:string;
      authChecks:{method:string;status:string;location:AnalysisLocation;resultEvidence?:{status:string;guardLocation:AnalysisLocation;userIdFilters:AnalysisLocation[];limitations:string[]}|null}[];clientTrace:AnalysisLocation[];policyLocations:AnalysisLocation[];
      filterLocations:AnalysisLocation[];enclosingFunction:AnalysisLocation|null;requestEntry?:AnalysisLocation|null;policyStates:string[];limitations:string[]}|null}[];
  findings:{findingId:string;ruleId:string;priority:'REVIEW_REQUIRED';comparisonPolicy:'NOT_COMPARED';table:string;location:AnalysisLocation;
    roles:string[];operations:string[];evidenceLocations:AnalysisLocation[];title:string;reason:string;recommendation:string;verificationSteps:string[];limitations:string[]}[];
}
