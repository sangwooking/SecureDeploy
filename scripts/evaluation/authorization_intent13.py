"""Evaluation-only intent interpretation. No product Finding, storage or policy edits."""
import hashlib
import json
import re
import copy

BASELINE='7dc85d29b27b438a74226e4444b01505bf7bb858'
ID=re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,63}\Z')
HASH=re.compile(r'[a-f0-9]{64}\Z')
FIELDS={'schemaVersion','intentRevision','approval','sourceSha256','entryFile','table','operation','assumedRole','ownerColumn','readScope','writeScope','editableColumns','protectedUpdateColumns','ownershipTransfer'}

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def validate(intent,source_hash):
    if not isinstance(intent,dict) or len(json.dumps(intent).encode())>8192 or set(intent)-FIELDS:return 'INVALID_INTENT'
    if type(intent.get('schemaVersion')) is not int or intent['schemaVersion']!=1 or type(intent.get('intentRevision')) is not int or intent['intentRevision']<1:return 'INVALID_INTENT_REVISION'
    if intent.get('approval')!='EVALUATION_CONFIRMED':return 'INTENT_NOT_CONFIRMED'
    if not isinstance(intent.get('sourceSha256'),str) or not HASH.fullmatch(intent['sourceSha256']) or intent['sourceSha256']!=source_hash:return 'STALE_SOURCE_BINDING'
    if intent.get('assumedRole') not in ['anon','authenticated']:return 'ROLE_CONTRACT_NOT_SUPPORTED'
    if not isinstance(intent.get('entryFile'),str) or len(intent['entryFile'])>256 or '..' in intent['entryFile'].split('/') or intent['entryFile'].startswith('/'):return 'INVALID_ENTRY_SCOPE'
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}\.[A-Za-z_][A-Za-z0-9_]{0,63}',str(intent.get('table',''))):return 'INVALID_TABLE_SCOPE'
    if intent.get('operation') not in ['SELECT','INSERT','UPDATE','DELETE']:return 'INVALID_OPERATION'
    if intent.get('readScope','UNKNOWN') not in ['UNKNOWN','OWNER_ONLY','PUBLIC']:return 'INVALID_READ_INTENT'
    if intent.get('writeScope','UNKNOWN') not in ['UNKNOWN','OWNER_ONLY','SHARED']:return 'INVALID_WRITE_INTENT'
    if intent.get('ownershipTransfer','UNKNOWN') not in ['UNKNOWN','FORBIDDEN','ALLOWED']:return 'INVALID_TRANSFER_INTENT'
    if intent.get('ownerColumn') is not None and (not isinstance(intent['ownerColumn'],str) or not ID.fullmatch(intent['ownerColumn'])):return 'INVALID_OWNER_MAPPING'
    for key in ['editableColumns','protectedUpdateColumns']:
        values=intent.get(key,[])
        if not isinstance(values,list) or len(values)>16 or any(not isinstance(v,str) or not ID.fullmatch(v) for v in values) or len(set(values))!=len(values):return 'INVALID_FIELD_SCOPE'
    if set(intent.get('editableColumns',[]))&set(intent.get('protectedUpdateColumns',[])):return 'CONFLICTING_INTENT'
    return None

def interpret(snapshot,intent,source_hash,mode):
    if mode not in ['SOURCE_ONLY','DECLARED_INTENT']:raise ValueError('MODE_REQUIRED')
    # This function deliberately receives no expected labels, case names or SQL oracle.
    result=dict(mode=mode,status='UNKNOWN',reasons=[],dimensions=[],originalPolicyCandidates=copy.deepcopy(snapshot.get('findings',[])),
      applicationInvocation='UNKNOWN',runtimeRole='UNKNOWN',deployedPolicies='UNKNOWN',actualVulnerability='NOT_VERIFIED',
      productFindingCreated=False,reviewDisposition='UNCHANGED',limitations=['CONDITIONAL_DECLARATION_INTERPRETATION_NOT_RUNTIME_AUTHORIZATION','EVALUATION_AUTHOR_CONFIRMATION_NOT_REAL_PROJECT_OWNER_APPROVAL'])
    if mode=='SOURCE_ONLY':
        result['status']='SOURCE_REVIEW' if result['originalPolicyCandidates'] else 'NO_SOURCE_CANDIDATE_OBSERVED'
        return result
    error=validate(intent,source_hash)
    if error:result['reasons']=[error];return result
    matches=[a for a in snapshot.get('accesses',[]) if a['location']['filePath']==intent['entryFile'] and a['table']==intent['table'] and a['operation']==intent['operation']]
    if len(matches)!=1:result['reasons']=['ACCESS_SCOPE_UNRESOLVED'];return result
    access=matches[0];auth=access.get('authorizationEvidence') or {};loc=access.get('policyLocation')
    if access.get('clientStatus')!='CLIENT_DECLARATION_LINKED' or not auth.get('requestEntry'):result['reasons']=['REQUEST_OR_CLIENT_LINK_MISSING'];return result
    if not any(c.get('method') in ['getUser','getClaims'] and (c.get('resultEvidence')or{}).get('status')=='IDENTITY_RESULT_GUARD_OBSERVED' for c in auth.get('authChecks',[])):
        result['reasons']=['AUTHENTICATION_RESULT_CONTEXT_UNKNOWN'];return result
    tables=[t for t in snapshot.get('tables',[]) if t['table']==intent['table'] and t['location']==loc]
    if len(tables)!=1 or tables[0]['rls']=='UNKNOWN':result['reasons']=['POLICY_CONTEXT_UNKNOWN'];return result
    table=tables[0];ops=[o for o in table['operations'] if o['role']==intent['assumedRole'] and o['operation']==intent['operation']]
    if len(ops)!=1 or ops[0]['state']=='UNKNOWN':result['reasons']=['POLICY_OPERATION_UNKNOWN'];return result
    op=ops[0];w=access.get('writeEvidence')or{};fields=w.get('dataFields',[])
    column=(w.get('columnUpdate')or{});roles=[r for r in column.get('roles',[]) if r['role']==intent['assumedRole']]
    col_fields={f['name']:f for f in roles[0]['fields']} if len(roles)==1 and column.get('status')=='DECLARATION_ONLY' else {}
    owner=intent.get('ownerColumn');same_owner=bool(owner) and op['columns']==[owner]
    def dimension(name,status,reason):result['dimensions'].append(dict(name=name,status=status,reason=reason))
    def col_granted(name):return col_fields.get(name,{}).get('grant') in ['TABLE_GRANT','COLUMN_GRANT']
    declared_grant=op['grant']=='EXPLICIT_GRANT' or intent['operation']=='UPDATE' and any(col_granted(f['name']) for f in fields)
    if not declared_grant:result['reasons']=['GRANT_NOT_ESTABLISHED_NOT_DENIAL'];return result
    if table['rls']!='ENABLED':result['reasons']=['ROW_POLICY_CONTRACT_NOT_ESTABLISHED'];return result
    def row_intent(name,value,condition):
        if value=='UNKNOWN':dimension(name,'UNKNOWN','INTENT_NOT_CONFIRMED')
        elif condition in ['ALLOW','AUTHENTICATION_ONLY']:dimension(name,'CONFLICT' if value=='OWNER_ONLY' else 'MATCH','BROAD_DECLARATION_VS_APPROVED_SCOPE')
        elif condition=='UID_COLUMN_EQUALITY' and same_owner:dimension(name,'MATCH','APPROVED_OWNER_COLUMN_EQUALITY_DECLARATION')
        else:dimension(name,'UNKNOWN','ROW_CONDITION_NOT_SUFFICIENT_FOR_REQUIREMENT')
    operation=intent['operation']
    if operation=='SELECT':row_intent('READ_SCOPE',intent.get('readScope','UNKNOWN'),op['using'])
    else:
        row_intent('WRITE_SCOPE',intent.get('writeScope','UNKNOWN'),op['check'] if operation=='INSERT' else op['using'])
        if operation=='UPDATE':
            if w.get('dataStatus')!='STATIC_FIELDS':dimension('UPDATE_FIELDS','UNKNOWN','DYNAMIC_UPDATE_FIELDS')
            else:
                editable=intent.get('editableColumns',[]);protected=intent.get('protectedUpdateColumns',[])
                for f in fields:
                    name=f['name']
                    if name in protected:
                        if col_granted(name) and f['source']=='REQUEST_CONTROLLED' and op['using'] in ['ALLOW','AUTHENTICATION_ONLY','UID_COLUMN_EQUALITY']:
                            dimension('PROTECTED_COLUMN:'+name,'CONFLICT','REQUEST_FIELD_AND_POSITIVE_UPDATE_GRANT_CONFLICT_WITH_APPROVED_REQUIREMENT')
                        else:dimension('PROTECTED_COLUMN:'+name,'UNKNOWN','COLUMN_OR_INPUT_CONDITION_NOT_ESTABLISHED')
                    elif name in editable:
                        dimension('EDITABLE_COLUMN:'+name,'MATCH' if col_granted(name) else 'UNKNOWN','EXPLICIT_EDIT_INTENT_AND_GRANT_DECLARATION')
                    elif name==owner and intent.get('ownershipTransfer')=='FORBIDDEN':
                        if same_owner and op['check']=='UID_COLUMN_EQUALITY':dimension('OWNERSHIP_TRANSFER','MATCH','REPLACEMENT_OWNER_EQUALITY_DECLARATION')
                        elif col_granted(name) and op['check'] in ['ALLOW','AUTHENTICATION_ONLY'] and f['source']=='REQUEST_CONTROLLED':dimension('OWNERSHIP_TRANSFER','CONFLICT','OWNER_REPLACEMENT_NOT_RESTRICTED_BY_DECLARED_CHECK')
                        else:dimension('OWNERSHIP_TRANSFER','UNKNOWN','TRANSFER_CONDITION_NOT_ESTABLISHED')
                    else:dimension('COLUMN:'+name,'UNKNOWN','FIELD_REQUIREMENT_NOT_CONFIRMED')
    statuses=[d['status'] for d in result['dimensions']]
    result['status']='CONFLICT' if 'CONFLICT' in statuses else 'UNKNOWN' if not statuses or 'UNKNOWN' in statuses else 'CONDITIONAL_MATCH'
    relevant=[f for f in result['originalPolicyCandidates'] if f.get('table')==intent['table'] and operation in f.get('operations',[]) and table['location'] in f.get('evidenceLocations',[])]
    if result['status']=='CONDITIONAL_MATCH' and intent.get('writeScope')=='SHARED' and operation=='UPDATE' and relevant:
        result['reviewDisposition']='SHARED_INTENT_ACKNOWLEDGED_FOR_THIS_ACCESS_ONLY'
        result['acknowledgedScope']=dict(entryFile=intent['entryFile'],table=intent['table'],operation=operation,assumedRole=intent['assumedRole'],
          fields=[f['name'] for f in fields],policyCandidateIds=[f['findingId'] for f in relevant],otherOperations='UNCHANGED')
    result['evidenceLocations']=list(dict.fromkeys(json.dumps(l,sort_keys=True) for l in [access['location'],table['location'],*table.get('grantLocations',[])[-8:]]))
    result['evidenceLocations']=[json.loads(v) for v in result['evidenceLocations']]
    return result
