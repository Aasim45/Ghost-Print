const fs=require('node:fs');const path=require('node:path');const {csv}=require('./server');
const root=path.resolve(__dirname,'..');const file=path.join(root,'output.csv');
const expected=require('./server').csv(fs.readFileSync(path.join(root,'dataset','deletion_requests.csv'),'utf8'));
const rows=csv(fs.readFileSync(file,'utf8'));const allowed={REPORT_REMAINING_RECORD:'PRESENT',REPORT_EXPOSED_PII:'PRESENT',REPORT_ACTIVE_DATA_FLOW:'ACTIVE',REPORT_RESTORE_RISK:'ACTIVE',DISABLE_DATA_FLOW:'DISABLED',BLOCK_RESTORE:'BLOCKED',DELETE_RECORD:'ABSENT',REDACT_RECORD:'REDACTED',ANONYMIZE_RECORD:'ANONYMIZED',VERIFY_RECORD_ABSENT:'ABSENT',VERIFY_RECORD_PRESENT:'PRESENT',VERIFY_RECORD_REDACTED:'REDACTED',VERIFY_RECORD_ANONYMIZED:'ANONYMIZED',VERIFY_DATA_FLOW_DISABLED:'DISABLED',VERIFY_RESTORE_BLOCKED:'BLOCKED'};
const order=Object.keys(allowed);const phase={FINDING:0,REMEDIATION:1,VERIFICATION:2};let errors=[];
if(rows.length!==expected.length)errors.push(`expected ${expected.length} output rows, got ${rows.length}`);
if(rows.map(r=>r.case_id).join('|')!==expected.map(r=>r.case_id).sort((a,b)=>a.localeCompare(b)).join('|'))errors.push('case IDs are missing, duplicated, or not sorted');
for(const row of rows){if(!['COMPLETE','INCOMPLETE','NOT_APPLICABLE'].includes(row.deletion_status)){errors.push(`${row.case_id}: invalid status`);continue;}
 let steps;try{steps=JSON.parse(row.steps_json)}catch{errors.push(`${row.case_id}: invalid steps JSON`);continue;}
 if(!Array.isArray(steps)){errors.push(`${row.case_id}: steps_json is not an array`);continue;}
 if(row.deletion_status==='NOT_APPLICABLE'&&steps.length)errors.push(`${row.case_id}: NOT_APPLICABLE must have []`);
 for(let i=0;i<steps.length;i++){
  const s=steps[i];if(s.step_no!==i+1)errors.push(`${row.case_id}: nonconsecutive step number`);
  if(Object.keys(s).sort().join('|')!=='evidence_id|operation|phase|resource_id|state|step_no|system_id')errors.push(`${row.case_id}: step fields differ from contract`);
  if(!(s.operation in allowed)||allowed[s.operation]!==s.state)errors.push(`${row.case_id}: unsupported operation/state pair`);
  if(!(s.phase in phase))errors.push(`${row.case_id}: invalid phase`);
  if(i){const a=steps[i-1],rank=x=>[phase[x.phase],order.indexOf(x.operation),x.system_id,x.resource_id].join('|');if(phase[a.phase]>phase[s.phase]||(phase[a.phase]===phase[s.phase]&&(order.indexOf(a.operation)>order.indexOf(s.operation)||(a.operation===s.operation&&(a.system_id.localeCompare(s.system_id)>0||(a.system_id===s.system_id&&a.resource_id.localeCompare(s.resource_id)>0))))))errors.push(`${row.case_id}: steps are out of order`);}
  if(s.phase==='FINDING'&&!s.evidence_id)errors.push(`${row.case_id}: finding lacks evidence reference`);
  if(s.phase!=='FINDING'&&row.deletion_status==='INCOMPLETE'&&s.evidence_id)errors.push(`${row.case_id}: proposed step must have empty evidence`);
 }
}
if(errors.length){console.error(errors.slice(0,30).join('\n'));process.exitCode=1;}else console.log(`Valid structure: ${rows.length} rows, exact schema, ordered steps, and allowed operation/state pairs.`);
