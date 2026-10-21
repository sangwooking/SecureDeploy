import type { AnalysisLocation } from './serverAnalysis';
export interface SupabaseAnalysis {
  schemaVersion:number;analyzerVersion:string;status:string;limitations:string[];
  budgetUsage?:Record<string,number>|null;
  files:{filePath:string;status:string;statements:number;limitations:string[]}[];
  tables:{scope:string;table:string;rls:string;force:string;location:AnalysisLocation;grantLocations:AnalysisLocation[];limitations:string[];
    policies:{name:string;command:string;mode:string;roles:string[];using:{kind:string;columns:string[]};check:{kind:string;columns:string[]};location:AnalysisLocation}[];
    operations:{role:string;operation:string;grant:string;using:string;check:string;columns:string[];state:string;candidate:boolean;policyLocations:AnalysisLocation[]}[];}[];
  clients:{location:AnalysisLocation;keySource:string;authContext:string;limitations:string[]}[];
  accesses:{location:AnalysisLocation;table:string;operation:string;clientStatus:string;clientLocation:AnalysisLocation|null;
    keySource:string;policyStatus:string;policyLocation:AnalysisLocation|null;limitations:string[];
    authorizationEvidence?:{state:string;clientContract:string;authStatus:string;effectiveRole:string;roleEvidence:string;
      authChecks:{method:string;status:string;location:AnalysisLocation}[];clientTrace:AnalysisLocation[];policyLocations:AnalysisLocation[];
      filterLocations:AnalysisLocation[];enclosingFunction:AnalysisLocation|null;policyStates:string[];limitations:string[]}|null}[];
  findings:{findingId:string;ruleId:string;priority:'REVIEW_REQUIRED';comparisonPolicy:'NOT_COMPARED';table:string;location:AnalysisLocation;
    roles:string[];operations:string[];evidenceLocations:AnalysisLocation[];title:string;reason:string;recommendation:string;verificationSteps:string[];limitations:string[]}[];
}
