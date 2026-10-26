// Conditional repository ACL declarations, never a verdict on the active DB role.
export function columnUpdateEvidence(access,tables,tick){
  if(access.operation!=='UPDATE')return null;
  const w=access.writeEvidence;
  const table=tables.find(t=>t.table===access.table&&t.location.filePath===access.policyLocation?.filePath&&t.location.line===access.policyLocation?.line);
  const known=w.dataStatus==='STATIC_FIELDS'&&!!w.dataFields.length;
  const roles=['anon','authenticated'].map(role=>{
    tick();const acl=table?.updatePrivileges?.find(p=>p.role===role);
    const established=known&&table?.rls!=='UNKNOWN'&&acl?.status==='DECLARATION_ONLY';
    return {role,tableGrant:established?acl.tableGrant:'UNKNOWN',fields:w.dataFields.map(f=>{
      tick();return {name:f.name,source:f.source,grant:!established?'UNKNOWN':acl.tableGrant==='EXPLICIT_GRANT'?'TABLE_GRANT':acl.columns.includes(f.name)?'COLUMN_GRANT':'NOT_ESTABLISHED'};
    })};
  });
  return {analyzerVersion:'column-update-v1',status:roles.some(r=>r.tableGrant!=='UNKNOWN')?'DECLARATION_ONLY':'UNKNOWN',
    roles,grantLocations:(table?.grantLocations??[]).slice(-8),
    limitations:['DECLARED_PRIVILEGES_NOT_EFFECTIVE_RUNTIME_PERMISSIONS','ROLE_INHERITANCE_OWNER_AND_ADMIN_UNKNOWN',
      'MISSING_GRANT_NOT_DENIAL_PROOF','SELECT_AND_QUERY_PREREQUISITES_NOT_VERIFIED','PROTECTED_PROPERTY_REQUIREMENTS_UNKNOWN',
      'ROW_POLICY_AND_COLUMN_PRIVILEGE_ARE_SEPARATE','COLUMN_EXISTENCE_AND_GRANTOR_UNKNOWN',...(!known?['DYNAMIC_UPDATE_FIELDS_UNKNOWN']:[])]};
}
