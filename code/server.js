const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { fileURLToPath } = require('node:url');
const { analyzePropagation } = require('./propagation');
const { buildAuditReasons } = require('./reasons');
const SUPPORTED_REASON_CODES = ['EVIDENCE_NOT_SUPPLIED', 'UNREADABLE_EVIDENCE', 'EVIDENCE_NOT_LINKED', 'EVIDENCE_AFTER_CUTOFF', 'INSUFFICIENT_TERMINAL_EVIDENCE', 'CONFLICTING_EVIDENCE', 'RESIDUAL_DATA_FOUND', 'CLEANUP_PENDING', 'RETENTION_PENDING', 'ACTIVE_DATA_FLOW', 'IDENTITY_MATCH_FAILED', 'MISSING_ACTIVITY', 'INCOMPLETE_WORKFLOW', 'UNKNOWN_CAUSE'];

const ROOT = path.resolve(__dirname, '..');
const DATA = path.join(ROOT, 'dataset');
const OUTPUT = path.join(ROOT, 'output.csv');
const PORT = Number(process.env.PORT || 8000);

function csv(text) {
  const rows = []; let row = [], field = '', quote = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote && c === '"' && text[i + 1] === '"') { field += '"'; i++; }
    else if (c === '"') quote = !quote;
    else if (c === ',' && !quote) { row.push(field); field = ''; }
    else if ((c === '\n' || c === '\r') && !quote) { if (c === '\r' && text[i + 1] === '\n') i++; row.push(field); if (row.some(x => x !== '')) rows.push(row); row = []; field = ''; }
    else field += c;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  const headers = rows.shift() || [];
  return rows.map(values => Object.fromEntries(headers.map((h, i) => [h, values[i] ?? ''])));
}
function load(name) { return csv(fs.readFileSync(path.join(DATA, name), 'utf8').replace(/^\uFEFF/, '')); }
function iso(s) { const n = Date.parse(s || ''); return Number.isFinite(n) ? n : 0; }
function esc(s) { return `"${String(s).replaceAll('"', '""')}"`; }
function norm(s) { return String(s ?? '').trim().toLocaleLowerCase('en-US'); }
function matchesRequestQuery(request, q) {
  if (!q) return true;
  if (norm(request?.case_id) === q) return true;
  return norm([request?.email, request?.request_text].join(' ')).includes(q);
}
function foldIntentText(s) { return norm(s).normalize('NFD').replace(/[\u0300-\u036f]/g, '').normalize('NFC'); }
function flatValues(obj, out = []) {
  if (obj && typeof obj === 'object') for (const [k, v] of Object.entries(obj)) {
    if (v && typeof v === 'object') flatValues(v, out); else if (v != null) out.push([k.toLowerCase(), String(v)]);
  }
  return out;
}
function readEvidence() {
  const manifest = load('evidence_files.csv');
  const supported = new Set(['.json', '.txt', '.log', '.sql', '.csv']);
  return manifest.map(item => {
    const filename = path.resolve(DATA, 'evidence', item.file_path.replace(/^evidence[\\/]/, ''));
    const relative = path.relative(path.join(DATA, 'evidence'), filename);
    if (relative.startsWith('..') || path.isAbsolute(relative)) return { ...item, error: 'Unsafe manifest path' };
    if (!supported.has(path.extname(filename).toLowerCase())) return { ...item, text: '', parsed: undefined, error: 'Unsupported evidence format' };
    try {
      const raw = fs.readFileSync(filename);
      const ext = path.extname(filename).toLowerCase();
      let text = raw.toString('utf8'); let parsed;
      if (ext === '.json') { try { parsed = JSON.parse(text); } catch {} }
      return { ...item, text, parsed, error: null };
    } catch (e) { return { ...item, error: e.message }; }
  });
}
function legacyDeletionIntent(text) {
  const t = norm(text);
  const positive = /\b(delet\w*|eras\w*|remov\w*|clos\w*|purge\w*|wip\w*|eliminat\w*)\b|\b(account|profile|data|personal details)\b.{0,36}\b(gone|removed|deleted|closed|erased)\b|\b(suppression|supprimer|effac\w*|löschen|loeschen|borrar|elimin\w*|apagar|削除|消去|抹消)\b|(?:アカウント|データ).{0,8}(?:削除|消去)|계정.{0,8}삭제/i.test(t);
  const negative = /\b(do not delete|don't delete|not delete|without deleting|instead of deleting|not a deletion|no deletion)\b/i.test(t);
  const alternative = /\b(access|export|correct|update|rectify|marketing opt.?out|unsubscribe|change my|reset my password)\b/i.test(t) && !positive;
  return positive && !negative && !alternative;
}
function deletionIntent(text) {
  const t = foldIntentText(text);
  const direct = [
    /\b(?:please|i want|i would like|i request|request\w*|would like|want|solicito|quero|quiero|je demande|je souhaite|ich mochte|vorrei)\b.{0,100}\b(?:delete\w*|erase\w*|remove\w*|close\w*|purge\w*|wipe\w*|eliminate\w*|deletion|erasure|exclusion|exclusao|eliminacao|borrar|eliminar|supprimer|effacer|loschen|cancellare|cancellazione|verwijder\w*)\b/,
    /\b(?:delete|erase|remove|close|purge|wipe|eliminate|deletion|erasure|exclusion|exclusao|eliminacao|borrar|eliminar|supprimer|effacer|loschen|cancellare|cancellazione|verwijder)\w*\b.{0,60}\b(?:my|meu|minha|meus|minhas|mi|mis|mon|ma|mes|mein|meine|mio|mia|miei|mijn)\b.{0,30}\b(?:account|conta|cuenta|compte|konto|dados|data|donnees|personal)\b/,
    /\b(?:exclusao|eliminacao|apagamento|supressao|borrado|eliminacion|effacement|suppression|loschung|cancellazione)\b.{0,60}\b(?:conta|cuenta|compte|konto|account|dados|data|donnees|personal)\b/,
    /(?:계정|데이터).{0,20}(?:삭제|제거)|(?:アカウント|データ).{0,20}(?:削除|消去)|(?:账号|账户|数据).{0,20}(?:删除|清除)/
  ];
  const positive = direct.some(pattern => pattern.test(t));
  const negative = /\b(?:do not delete|don't delete|not delete|without deleting|instead of deleting|not a deletion|no deletion|nao exclua|nao apagar|sem excluir|sin borrar|ne supprimez pas|nicht loschen)\b/i.test(t);
  const alternative = /\b(?:access|export|correct|update|rectify|marketing opt.?out|unsubscribe|change my|reset my password|acesso|exportacao|correcao|atualizar|marketing|acesso aos dados)\b/i.test(t) && !positive;
  return positive && !negative && !alternative;
}
function parseSqlValues(line){
  const m=line.match(/^\s*INSERT\s+INTO\s+["`\w]+\s+VALUES\s*\((.*)\);\s*$/i);if(!m)return null;
  const out=[];let v='',q=false;
  for(let i=0;i<m[1].length;i++){const c=m[1][i];if(c==="'"&&q&&m[1][i+1]==="'"){v+="'";i++;}else if(c==="'")q=!q;else if(c===','&&!q){out.push(v);v='';}else v+=c;}out.push(v);return out;
}
function parseSqlSchema(text){
  const schemas=new Map();const re=/CREATE\s+TABLE\s+["`]?([\w]+)["`]?\s*\(([\s\S]*?)\);/gi;let m;
  while((m=re.exec(text))){const columns=[];for(const row of m[2].split(',')){const x=row.trim().match(/^["`]?([A-Za-z_]\w*)["`]?\s+(?:TEXT|INTEGER|REAL|BLOB|NUMERIC|BOOLEAN)/i);if(x)columns.push(x[1]);}schemas.set(m[1],columns);}
  return schemas;
}
function identityIndex() {
  const users = load('user_identities.csv'); const audits = load('user_audit_log.csv');
  const byId = new Map(users.map(u => [u.user_id, { ...u, identifiers: new Set([u.email, u.email_hash, u.phone, u.name].filter(Boolean).map(norm)), history: [] }]));
  for (const a of audits) {
    const p = byId.get(a.user_id); if (!p) continue;
    p.history.push(a);
    for (const value of [a.old_value, a.new_value]) if (value) p.identifiers.add(norm(value));
  }
  return byId;
}
function evidenceMatches(profile, evidence) {
  const ids = profile.identifiers;
  const terms = evidence.parsed ? flatValues(evidence.parsed) : evidence.text.split(/\r?\n/).map(x => ['', x]);
  const matches = [];
  for (const [key, value] of terms) {
    const n = norm(value);
    if (ids.has(n)) matches.push({ kind: key, value });
  }
  return matches;
}
function isResourceIdentifier(value) {
  return /^(?:account|search|support|analytics|telemetry|export|backup|audit_record|message|attachment|cache|replica|archive|job|data_flow)_[A-Za-z0-9_-]+$/i.test(String(value || ''));
}
function resourceFromObject(value) {
  const candidate = value?.resource_id || value?.resource;
  return isResourceIdentifier(candidate) ? String(candidate) : null;
}
function observations(profile, evidence) {
  const wanted=profile.identifiers; const out=[];
  const scan=value=>{
    if(Array.isArray(value)){for(const x of value)scan(x);return;}
    if(!value||typeof value!=='object')return;
    const fields=flatValues(value); const hits=fields.filter(([,v])=>wanted.has(norm(v)));
    if(hits.length){
      const resource=resourceFromObject(value);
      if(resource) out.push({resource:String(resource), object:value, hits});
    }
    for(const v of Object.values(value)) if(v&&typeof v==='object')scan(v);
  };
  if(evidence.parsed) scan(evidence.parsed);
  else for(const line of evidence.text.split(/\r?\n/)){
    const terms=[...wanted].filter(x=>x&&line.toLocaleLowerCase('en-US').includes(x));
    if(!terms.length)continue;
    const ids=line.match(/\b(?:account|search|support|analytics|telemetry|export|backup|audit_record|message|attachment|cache|replica|archive|job|data_flow)_[A-Za-z0-9_-]+\b/g)||[];
    for(const resource of new Set(ids))out.push({resource,object:{line},hits:terms.map(value=>['identifier',value])});
  }
  return out;
}
const operationRank = new Map(['REPORT_REMAINING_RECORD','REPORT_EXPOSED_PII','REPORT_ACTIVE_DATA_FLOW','REPORT_RESTORE_RISK','DISABLE_DATA_FLOW','BLOCK_RESTORE','DELETE_RECORD','REDACT_RECORD','ANONYMIZE_RECORD','VERIFY_RECORD_ABSENT','VERIFY_RECORD_PRESENT','VERIFY_RECORD_REDACTED','VERIFY_RECORD_ANONYMIZED','VERIFY_DATA_FLOW_DISABLED','VERIFY_RESTORE_BLOCKED'].map((x,i)=>[x,i]));
function sortSteps(steps) {
  const phase = { FINDING: 0, REMEDIATION: 1, VERIFICATION: 2 };
  return steps.sort((a,b) => phase[a.phase]-phase[b.phase] || operationRank.get(a.operation)-operationRank.get(b.operation) || a.system_id.localeCompare(b.system_id) || a.resource_id.localeCompare(b.resource_id));
}
function makeStep(phase, system, resource, operation, state, evidence) { return { step_no: 0, phase, system_id: system || 'unknown', resource_id: resource || 'unknown', operation, state, evidence_id: evidence || '' }; }
function investigationVerification(resource) {
  const action = String(resource?.required_action || '').toUpperCase();
  if (action === 'REDACT') return makeStep('VERIFICATION', resource.system_id, resource.resource_id, 'VERIFY_RECORD_REDACTED', 'REDACTED', '');
  if (action === 'ANONYMIZE') return makeStep('VERIFICATION', resource.system_id, resource.resource_id, 'VERIFY_RECORD_ANONYMIZED', 'ANONYMIZED', '');
  if (action === 'RETAIN') return makeStep('VERIFICATION', resource.system_id, resource.resource_id, 'VERIFY_RECORD_PRESENT', 'PRESENT', '');
  return makeStep('VERIFICATION', resource.system_id, resource.resource_id, 'VERIFY_RECORD_ABSENT', 'ABSENT', '');
}

class Ghostprints {
  constructor() {
    this.requests = load('deletion_requests.csv'); this.sample = load('sample_deletion_requests.csv');
    this.identities = identityIndex(); this.evidence = readEvidence(); this.rules = load('deletion_rules.csv');
    this.activity = load('system_activity.csv'); this.results = new Map(); this.explained = new Map(); this.datasets = [];
    this.manifest = this.evidence.map(e => ({ file_id:e.file_id, file_path:e.file_path, origin:e.origin, captured_at:e.captured_at, readable:!e.error, error:e.error || null }));
    this.observationIndex=this.buildObservationIndex();
  }
  buildObservationIndex() {
    const terms=new Map();
    for(const profile of this.identities.values()) for(const value of profile.identifiers){
      if(!terms.has(value))terms.set(value,[]); terms.get(value).push(profile.user_id);
    }
    const index=new Map([...this.identities.keys()].map(id=>[id,[]]));
    const add=(e,resource,object,values)=>{
      const hitUsers=new Set();const hits=[];
      for(const value of values){const n=norm(value);const ids=terms.get(n);if(ids)for(const id of ids){hitUsers.add(id);hits.push([String(value),id]);}}
      for(const id of hitUsers)index.get(id).push({evidence:e,resource,object,hits:hits.filter(x=>x[1]===id)});
    };
    for(const e of this.evidence){if(e.error)continue;
      if(e.parsed){
        const scan=value=>{if(Array.isArray(value)){for(const x of value)scan(x);return;}if(!value||typeof value!=='object')return;
          const values=flatValues(value).map(x=>x[1]);const resource=resourceFromObject(value);
          if(resource)add(e,String(resource),value,values);
          for(const child of Object.values(value))if(child&&typeof child==='object')scan(child);
        };scan(e.parsed);
      }else{
        const schemas=path.extname(e.file_path).toLowerCase()==='.sql'?parseSqlSchema(e.text):new Map();
        for(const line of e.text.split(/\r?\n/)){
          if(path.extname(e.file_path).toLowerCase()==='.sql'){
            const values=parseSqlValues(line);if(values?.length>=4){
              const tableMatch=line.match(/INSERT\s+INTO\s+["`]?([\w]+)["`]?\s+VALUES/i);const table=tableMatch?.[1]||'';
              let record;try{record=JSON.parse(values[3]);}catch{}
              if(record&&typeof record==='object')record={...record,origin_system:values[1],collection_name:values[2]};
              else {const columns=schemas.get(table)||[];record=Object.fromEntries(columns.map((key,i)=>[key,values[i]]));record.collection_name=table;}
              const resource=String(record.resource_id||values[0]);if(resource)add(e,resource,record,flatValues(record).map(x=>x[1]));
            }
            continue;
          }
          const candidates=[...(line.match(/[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/g)||[]),...(line.match(/\buser_\d+\b/gi)||[]),...(line.match(/\b[a-f0-9]{64}\b/gi)||[]),...(line.match(/\+?[\d][\d ()-]{7,}\d/g)||[])];
          if(!candidates.length)continue;
          const resources=line.match(/\b(?:account|search|support|analytics|telemetry|export|backup|audit_record|message|attachment|cache|replica|archive|job|data_flow)_[A-Za-z0-9_-]+\b/g)||[];
          for(const resource of new Set(resources))add(e,resource,{line},candidates);
        }
      }
    }
    return index;
  }
  analyze(req) {
    if (!deletionIntent(req.request_text)) return { case_id:req.case_id, deletion_status:'NOT_APPLICABLE', steps:[], investigation_state:'NO_INVESTIGATION_REQUIRED', investigation_explanation:'No investigation required because the request does not clearly authorize deletion.', explanation:'Request text does not clearly authorize deletion.' };
    const matches = [...this.identities.values()].filter(p => p.identifiers.has(norm(req.email)));
    if (matches.length !== 1) return { case_id:req.case_id, deletion_status:'INCOMPLETE', steps:[], investigation_state:'INVESTIGATION_REQUIRED_IDENTITY_UNRESOLVED', investigation_explanation:'Investigation requires a unique identity match before affected resources can be enumerated.', explanation:matches.length ? 'Identity is ambiguous; findings were not merged.' : 'No unique identity profile could be resolved.' , identity_ambiguous: matches.length > 1 };
    const profile = matches[0]; const cutoff = iso(req.audit_at); const found = [];
    for (const observation of this.observationIndex.get(profile.user_id)||[]) {
      const e=observation.evidence;if(iso(e.captured_at)>cutoff)continue;
      {
        const {resource,object}=observation; const encoded=JSON.stringify(object); const system=this.systemFor(resource,encoded);
        if (/NOT_FOUND|"deleted"\s*:\s*true|"state"\s*:\s*"ABSENT"/i.test(encoded)) continue;
        const category=String(object.data_category||object.category||'').toUpperCase();
        const collection=String(object.collection_name||'').toLowerCase();
        const kind=category||(/customer_profiles/.test(collection)||/account_/.test(resource)?'USER_PROFILE':/search/.test(collection)||/search_/.test(resource)?'SEARCH_INDEX_ENTRY':/analytics|telemetry/.test(collection)||/analytics_|telemetry_/.test(resource)?'ANALYTICS_PROFILE':/support.*attachment|attachment/.test(collection)?'SUPPORT_ATTACHMENT':/support/.test(collection)||/support_/.test(resource)?'SUPPORT_MESSAGE':/export/.test(collection)||/export_/.test(resource)?'USER_EXPORT':/backup|archive/.test(collection)||/backup_|archive_/.test(resource)?'BACKUP_ARCHIVE':/security_audit|audit_record_/.test(collection+' '+resource)?'SECURITY_AUDIT_LOG':'');
        const policy=this.policyAction(kind);
        const isRetained=policy==='RETAIN';
        const hasPII=observation.hits.some(([value])=>norm(value)!==norm(profile.user_id)) || /"(?:email|phone|full_name|name|email_hash)"\s*:\s*"[^"\s]+/i.test(encoded);
        if(isRetained) continue;
        if(/data_flow|sync|import/i.test(resource) && /ACTIVE|ENABLED|RUNNING/i.test(encoded)) found.push({resource,system,op:'REPORT_ACTIVE_DATA_FLOW',state:'ACTIVE',evidence:e.file_id,category:kind});
        else if(/backup|archive/i.test(resource) && /ACTIVE|ENABLED|RESTORABLE/i.test(encoded)) found.push({resource,system,op:'REPORT_RESTORE_RISK',state:'ACTIVE',evidence:e.file_id,category:kind});
        else if(policy==='DELETE' && /(?:ACTIVE|IDENTIFIABLE|FOUND|PRESENT|SUCCESS)/i.test(encoded)) found.push({resource,system,op:'REPORT_REMAINING_RECORD',state:'PRESENT',evidence:e.file_id,category:kind});
        else if(policy==='REDACT' && hasPII) found.push({resource,system,op:'REPORT_EXPOSED_PII',state:'PRESENT',evidence:e.file_id,category:kind});
        else if(policy==='ANONYMIZE' && hasPII) found.push({resource,system,op:'REPORT_EXPOSED_PII',state:'PRESENT',evidence:e.file_id,category:kind});
      }
    }
    // Activity is contextual only: require a related, independently matched evidence item.
    const steps = [];
    for (const f of dedupe(found)) steps.push(makeStep('FINDING',f.system,f.resource,f.op,f.state,f.evidence));
    let incomplete = steps.length > 0 || !(this.observationIndex.get(profile.user_id)||[]).some(o=>iso(o.evidence.captured_at)<=cutoff);
    let investigation_state = steps.length ? 'INVESTIGATION_PARTIALLY_COMPLETED' : 'INVESTIGATION_REQUIRED_NOT_PERFORMED';
    if (incomplete) {
      for (const f of dedupe(found)) {
        const op = f.op==='REPORT_ACTIVE_DATA_FLOW'?'DISABLE_DATA_FLOW':f.op==='REPORT_RESTORE_RISK'?'BLOCK_RESTORE':f.category==='ANALYTICS_PROFILE'||f.category==='PRODUCT_TELEMETRY' ? 'ANONYMIZE_RECORD' : f.op === 'REPORT_EXPOSED_PII' ? 'REDACT_RECORD' : 'DELETE_RECORD';
        const state = op === 'REDACT_RECORD' ? 'REDACTED' : op==='ANONYMIZE_RECORD'?'ANONYMIZED':'ABSENT';
        const remediationState=op==='DISABLE_DATA_FLOW'?'DISABLED':op==='BLOCK_RESTORE'?'BLOCKED':state;
        steps.push(makeStep('REMEDIATION',f.system,f.resource,op,remediationState,''));
        const verify = op==='DISABLE_DATA_FLOW'?'VERIFY_DATA_FLOW_DISABLED':op==='BLOCK_RESTORE'?'VERIFY_RESTORE_BLOCKED':op === 'REDACT_RECORD' ? 'VERIFY_RECORD_REDACTED' : op==='ANONYMIZE_RECORD'?'VERIFY_RECORD_ANONYMIZED':'VERIFY_RECORD_ABSENT';
        steps.push(makeStep('VERIFICATION',f.system,f.resource,verify,remediationState,''));
      }
      if (!steps.length) {
        const resources = this.propagation(req).resources || [];
        const uniqueResources = new Map(resources.map(resource => [`${resource.system_id}/${resource.resource_id}`, resource]));
        for (const resource of uniqueResources.values()) steps.push(investigationVerification(resource));
        if (steps.length) investigation_state = 'INVESTIGATION_REQUIRED_NOT_PERFORMED';
        else investigation_state = 'INVESTIGATION_REQUIRED_NO_ATTRIBUTABLE_RESOURCES';
      }
    } else if (!incomplete) {
      const file = this.evidence.find(e => e.file_path.includes('customer_account_handover') && iso(e.captured_at) <= cutoff && norm(e.text).includes(norm(req.email)));
      if (file) {
        const line = file.text.split(/\r?\n/).find(x => norm(x).includes(norm(req.email)) && /NOT_FOUND|ANONYMIZED|REDACTED|BLOCKED|DISABLED/i.test(x));
        if (line) { const m=line.match(/\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|/); if(m) steps.push(makeStep('VERIFICATION',m[1].trim(),m[2].trim(),'VERIFY_RECORD_ABSENT','ABSENT',file.file_id)); }
      }
      if(!steps.length) {
        incomplete = true;
        const resources = this.propagation(req).resources || [];
        const uniqueResources = new Map(resources.map(resource => [`${resource.system_id}/${resource.resource_id}`, resource]));
        for (const resource of uniqueResources.values()) steps.push(investigationVerification(resource));
        if (steps.length) investigation_state = 'INVESTIGATION_REQUIRED_NOT_PERFORMED';
      }
      if(!steps.length) return { case_id:req.case_id, deletion_status:'INCOMPLETE', steps:[], investigation_state:'INVESTIGATION_REQUIRED_NO_ATTRIBUTABLE_RESOURCES', investigation_explanation:'Insufficient attributable resource data was available to create a resource-level investigation task.', explanation:'No policy-compliant verification evidence established the final state by the audit cutoff.', missing_evidence:true };
    } else {
      return { case_id:req.case_id, deletion_status:'INCOMPLETE', steps:[], explanation:'Evidence for this identity is missing or unreadable by the audit cutoff; absence cannot be verified.', missing_evidence:true };
    }
    sortSteps(steps); steps.forEach((s,i)=>s.step_no=i+1);
    if (!incomplete) investigation_state = steps.length ? 'INVESTIGATION_COMPLETED_WITH_VERIFICATION' : 'INVESTIGATION_REQUIRED_NOT_PERFORMED';
    return { case_id:req.case_id, deletion_status:incomplete?'INCOMPLETE':'COMPLETE', steps, investigation_state, investigation_explanation: steps.length ? 'Investigation tasks identify the resource-level checks still required; empty evidence_id means the task is not completed.' : 'Insufficient attributable resource data was available to create a resource-level investigation task.', explanation:incomplete?`${steps.filter(s=>s.phase==='FINDING').length} evidence-linked residual identifier occurrence(s) were found.`:'No direct evidence match was found in the readable evidence available by the audit cutoff; this is not, by itself, proof of absence.' };
  }
  propagation(req) {
    const matches = [...this.identities.values()].filter(profile => profile.identifiers.has(norm(req?.email)));
    if (matches.length !== 1) {
      return {
        version: 1,
        case_id: req?.case_id || '',
        case_status: 'UNKNOWN',
        requested_at: iso(req?.requested_at) ? new Date(iso(req.requested_at)).toISOString() : null,
        audit_at: iso(req?.audit_at) ? new Date(iso(req.audit_at)).toISOString() : null,
        processing_start_at: null,
        processing_delay_ms: null,
        verified_completion_at: null,
        verified_propagation_ms: null,
        resources: [],
        errors: [{
          code: matches.length ? 'AMBIGUOUS_IDENTITY' : 'IDENTITY_NOT_FOUND',
          message: matches.length ? 'Propagation could not be attributed to one identity.' : 'No unique identity profile was resolved.',
          resource_id: null,
          evidence_id: null
        }]
      };
    }
    const profile = matches[0];
    const result = analyzePropagation({
      request: req,
      profile,
      observations: this.observationIndex.get(profile.user_id) || [],
      activities: this.activity,
      rules: this.rules,
      systemFor: this.systemFor.bind(this),
      policyAction: this.policyAction.bind(this)
    });
    const profileObservations = this.observationIndex.get(profile.user_id) || [];
    for (const resource of result.resources) {
      const system = resource.system_id;
      const activityDates = new Set(this.activity.filter(item => item.resource_id === resource.resource_id && iso(item.event_time) <= iso(req.audit_at)).map(item => String(item.event_time || '').slice(0, 10)));
      resource.unreadable_evidence_ids = this.evidence.filter(item => !item.parsed && item.error && iso(item.captured_at) <= iso(req.audit_at) && activityDates.has(String(item.captured_at || '').slice(0, 10)) && (String(item.origin || '').toLowerCase().includes(String(system).split('_')[0]) || String(item.file_path || '').toLowerCase().includes(String(system).split('_')[0]))).map(item => item.file_id);
      resource.evidence_supplied_elsewhere = !resource.evidence_ids.length && !resource.post_cutoff_evidence_ids?.length && profileObservations.some(item => this.systemFor(item.resource, JSON.stringify(item.object)) === system && iso(item.evidence.captured_at) <= iso(req.audit_at));
    }
    return result;
  }
  systemFor(resource, context='') {
    const map = [['account','account_service'],['search','search_service'],['support','support_platform'],['analytics','analytics_platform'],['telemetry','analytics_platform'],['export','export_service'],['backup','backup_service'],['audit_record','security_service'],['data_flow','integration_service'],['cache','cache_service'],['archive','archive_service']];
    return (map.find(([p])=>resource.startsWith(p))||[])[1] || (context.match(/(?:account_service|search_service|support_platform|analytics_platform|security_service|backup_service|export_service|integration_service)/)||[])[0] || 'unknown';
  }
  policyAction(category) { return this.rules.find(r=>r.data_category.toUpperCase()===String(category).toUpperCase())?.required_action.toUpperCase()||''; }
  explain(req, result) {
    if (result.deletion_status !== 'INCOMPLETE') return { ...result, reasons: [], reason_summary: '' };
    const profile = [...this.identities.values()].find(candidate => candidate.identifiers.has(norm(req?.email)));
    const propagation = this.propagation(req);
    const reasons = buildAuditReasons({ request: req, result, propagation, manifest: this.evidence, profile, activities: this.activity });
    const trace = this.trace(req, result, propagation, profile);
    return { ...result, propagation, pipeline_trace: trace, reasons, reason_summary: reasons.length ? `${reasons.length} diagnostic cause${reasons.length === 1 ? '' : 's'}` : '' };
  }
  trace(req, result, propagation, profile) {
    const cutoff = iso(req?.audit_at);
    const allObservations = profile ? (this.observationIndex.get(profile.user_id) || []) : [];
    const atCutoff = allObservations.filter(item => iso(item.evidence?.captured_at) <= cutoff);
    const activities = profile ? this.activity.filter(item => item.details && [...profile.identifiers].some(id => norm(item.details).includes(norm(id)))) : [];
    return {
      identity_matching: { status: profile ? 'RESOLVED' : 'UNRESOLVED', user_id: profile?.user_id || null, identifier_count: profile?.identifiers?.size || 0 },
      evidence_matching: { supplied_observations: allObservations.length, observations_at_cutoff: atCutoff.length, post_cutoff_observations: allObservations.filter(item => iso(item.evidence?.captured_at) > cutoff).length, readable: this.evidence.filter(item => !item.error).length, unreadable: this.evidence.filter(item => item.error).length },
      activity_analysis: { linked_activity_count: activities.length, at_cutoff: activities.filter(item => iso(item.event_time) <= cutoff).length, after_cutoff: activities.filter(item => iso(item.event_time) > cutoff).length, resource_count: propagation?.resources?.length || 0 },
      policy_evaluation: { resources: (propagation?.resources || []).map(item => ({ system_id: item.system_id, resource_id: item.resource_id, required_action: item.required_action, state: item.state })) },
      step_generation: { finding_steps: (result.steps || []).filter(step => step.phase === 'FINDING').length, total_steps: (result.steps || []).length, zero_steps: !(result.steps || []).length }
    };
  }
  resultFor(req) {
    if (this.explained.has(req.case_id)) return this.explained.get(req.case_id);
    const result = this.explain(req, this.results.get(req.case_id)||this.analyze(req));
    this.explained.set(req.case_id, result);
    return result;
  }
  all() { return this.requests.map(r=>this.resultFor(r)); }
  run() { this.explained.clear(); for (const r of this.requests) this.results.set(r.case_id,this.analyze(r)); return this.all(); }
  dashboard() {
    const cases=this.all(); const counts={COMPLETE:0,INCOMPLETE:0,NOT_APPLICABLE:0}; cases.forEach(c=>counts[c.deletion_status]++);
    const findings=cases.flatMap(c=>c.steps.filter(s=>s.phase==='FINDING'));
    return { total_requests:cases.length, completed:counts.COMPLETE, incomplete:counts.INCOMPLETE, not_applicable:counts.NOT_APPLICABLE, remaining_records:findings.length, active_flows:findings.filter(x=>x.operation==='REPORT_ACTIVE_DATA_FLOW').length, restore_risks:findings.filter(x=>x.operation==='REPORT_RESTORE_RISK').length, by_system:Object.fromEntries([...new Set(findings.map(f=>f.system_id))].map(s=>[s,findings.filter(f=>f.system_id===s).length])), recent:cases.slice(-10) };
  }
  reasonCoverage() {
    const allCases = this.all();
    const cases = allCases.filter(item => item.deletion_status === 'INCOMPLETE');
    const generic = new Set(['UNKNOWN_CAUSE']);
    const counts = new Map(); const genericFallbacks = new Map();
    for (const item of cases) for (const reason of item.reasons || []) {
      const root = reason.root_cause || reason.code;
      counts.set(root, (counts.get(root) || 0) + 1);
      if (generic.has(reason.code)) genericFallbacks.set(root, (genericFallbacks.get(root) || 0) + 1);
    }
    return {
      total_cases: this.requests.length,
      total_incomplete_cases: cases.length,
      cases_receiving_generated_investigation_tasks: cases.filter(item => item.investigation_state === 'INVESTIGATION_REQUIRED_NOT_PERFORMED' && (item.steps || []).length > 0).length,
      cases_with_zero_steps_appropriate: allCases.filter(item => item.investigation_state === 'NO_INVESTIGATION_REQUIRED' || item.investigation_state === 'INVESTIGATION_REQUIRED_NO_ATTRIBUTABLE_RESOURCES').length,
      cases_with_detailed_reasons: cases.filter(item => (item.reasons || []).some(reason => !generic.has(reason.code))).length,
      cases_with_only_generic_reasons: cases.filter(item => item.reasons?.length && item.reasons.every(reason => generic.has(reason.code))).length,
      cases_with_generic_reasons: cases.filter(item => item.reasons?.some(reason => generic.has(reason.code))).length,
      cases_with_unknown_causes: cases.filter(item => item.reasons?.some(reason => reason.code === 'UNKNOWN_CAUSE')).length,
      cases_with_no_reasons: cases.filter(item => !item.reasons?.length).length,
      cases_with_zero_investigation_steps: cases.filter(item => !(item.steps || []).length).length,
      reason_counts: Object.fromEntries(SUPPORTED_REASON_CODES.map(code => [code, counts.get(code) || 0])),
      most_frequent_root_causes: [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([code, count]) => ({ code, count })),
      most_common_generic_fallback_reasons: [...genericFallbacks.entries()].sort((a, b) => b[1] - a[1]).map(([code, count]) => ({ code, count }))
    };
  }
  propagationSummary(query = '') {
    const q = norm(query);
    const requests = this.requests.filter(request => matchesRequestQuery(request, q));
    const resources = new Map();
    for (const request of requests) for (const resource of this.propagation(request).resources || []) {
      const key = `${request.case_id}/${resource.system_id}/${resource.resource_id}`;
      if (!resources.has(key)) resources.set(key, { ...resource, case_id: request.case_id, audit_at: request.audit_at });
    }
    const values = [...resources.values()];
    const pending = values.filter(resource => ['PENDING', 'FAILED'].includes(resource.state) && Number.isFinite(Date.parse(resource.processing_start_at || '')) && Number.isFinite(Date.parse(resource.audit_at || '')) && Date.parse(resource.audit_at) >= Date.parse(resource.processing_start_at));
    const stateCounts = values.reduce((counts, resource) => {
      counts[resource.state] = (counts[resource.state] || 0) + 1;
      return counts;
    }, {});
    return {
      matching_cases: requests.length,
      resources_checked: values.length,
      unknown_or_unverified: values.filter(resource => /UNKNOWN|UNVERIFIED/.test(resource.state || '')).length,
      pending_cleanup: pending.length,
      state_counts: stateCounts,
      verified_resources: values.filter(resource => /_VERIFIED$/.test(resource.state || '')).length,
      failed_resources: stateCounts.FAILED || 0,
      pending_resources: stateCounts.PENDING || 0,
      conflicting_resources: stateCounts.CONFLICTING || 0
    };
  }
  export() {
    const rows=this.all().slice().sort((a,b)=>a.case_id.localeCompare(b.case_id));
    return 'case_id,deletion_status,steps_json\n'+rows.map(c=>[c.case_id,c.deletion_status,esc(JSON.stringify(c.steps))].join(',')).join('\n')+'\n';
  }
}
function dedupe(items) { const seen=new Set(); return items.filter(x=>{const k=[x.resource,x.system,x.op,x.evidence].join('|'); if(seen.has(k)) return false; seen.add(k); return true;}); }
const app = new Ghostprints();
const MIME = { '.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.svg':'image/svg+xml' };
const server = http.createServer((req,res)=>{
  res.setHeader('Access-Control-Allow-Origin','*'); res.setHeader('Access-Control-Allow-Headers','Content-Type'); res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');
  if(req.method==='OPTIONS'){res.writeHead(204);return res.end();}
  const url=new URL(req.url,'http://localhost'); const parts=url.pathname.split('/').filter(Boolean);
  const json=(code,value)=>{res.writeHead(code,{'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify(value));};
  if(url.pathname==='/api/health') return json(200,{status:'ok',product:'GHOSTPRINTS',requests:app.requests.length,evidence_files:app.manifest.length});
  if(url.pathname==='/api/dashboard/summary') return json(200,app.dashboard());
  if(url.pathname==='/api/datasets') return json(200,[{dataset_id:'official-challenge',request_count:app.requests.length,evidence_count:app.manifest.length,files:app.manifest}]);
  if(url.pathname==='/api/datasets/official-challenge') return json(200,{dataset_id:'official-challenge',request_count:app.requests.length,evidence_count:app.manifest.length,manifest:app.manifest,missing:app.manifest.filter(f=>!f.readable)});
  if(url.pathname==='/api/investigations/run' && req.method==='POST') return json(200,{processed:app.requests.length,results:app.run().length});
  if(url.pathname==='/api/investigations') {
    const q=norm(url.searchParams.get('q')||''); const status=url.searchParams.get('status');
    const out=app.all().filter(c=>{const r=app.requests.find(x=>x.case_id===c.case_id); return (!status||c.deletion_status===status)&&matchesRequestQuery(r, q);});
    const offset=Math.max(0,Number(url.searchParams.get('offset')||0)); const limit=Math.min(100,Math.max(1,Number(url.searchParams.get('limit')||25)));
    return json(200,{total:out.length,items:out.slice(offset,offset+limit).map(c=>({...c,request:app.requests.find(r=>r.case_id===c.case_id)}))});
  }
  if(parts[0]==='api'&&parts[1]==='investigations'&&parts[2]) {
    const c=app.all().find(x=>x.case_id===parts[2]); if(!c) return json(404,{error:'Case not found'});
    if(parts[3]==='propagation') return json(200,app.propagation(app.requests.find(x=>x.case_id===c.case_id)));
    if(parts[3]==='evidence') return json(200,{case_id:c.case_id,items:c.steps.map(s=>s.evidence_id).filter(Boolean).map(id=>app.manifest.find(f=>f.file_id===id)).filter(Boolean)});
    if(parts[3]==='timeline') return json(200,{case_id:c.case_id,request:app.requests.find(x=>x.case_id===c.case_id),steps:c.steps});
    if(parts[3]==='graph') return json(200,{nodes:c.steps.map(s=>({id:s.resource_id,label:s.resource_id,system_id:s.system_id,state:s.state,evidence_id:s.evidence_id})),edges:[]});
    if(parts[3]==='risks') return json(200,c.steps.filter(s=>s.phase==='FINDING'));
    if(parts[3]==='remediation') return json(200,c.steps.filter(s=>s.phase!=='FINDING'));
    return json(200,{...c,request:app.requests.find(x=>x.case_id===c.case_id)});
  }
  if(url.pathname==='/api/reports/export') { const body=app.export(); res.writeHead(200,{'Content-Type':'text/csv; charset=utf-8','Content-Disposition':'attachment; filename="output.csv"'}); return res.end(body); }
  if(url.pathname==='/api/reports/propagation-summary') return json(200,app.propagationSummary(url.searchParams.get('q') || ''));
  if(url.pathname==='/api/reports/reason-coverage') return json(200,app.reasonCoverage());
  if(url.pathname==='/api/evidence') return json(200,app.manifest);
  if(req.method==='POST'&&url.pathname==='/api/datasets/upload') return json(400,{error:'Upload is disabled for this challenge build. Evidence ingestion is read-only and uses the participant dataset manifest.'});
  const filename=parts.length?path.resolve(__dirname,'frontend',...parts):path.join(__dirname,'frontend','index.html');
  const rel=path.relative(path.join(__dirname,'frontend'),filename); if(rel.startsWith('..')||path.isAbsolute(rel)) return json(403,{error:'Invalid path'});
  fs.readFile(filename,(err,content)=>{if(err){res.writeHead(404);return res.end('Not found');}res.writeHead(200,{'Content-Type':MIME[path.extname(filename)]||'application/octet-stream'});res.end(content);});
});
if (require.main===module) {
  if(process.argv.includes('--export')){fs.writeFileSync(OUTPUT,app.export(),'utf8');console.log(`Wrote ${app.requests.length} rows to ${OUTPUT}`);}
  else if(process.argv.includes('--evaluate-sample')){
    const expected=load('sample_output.csv');const requests=load('sample_deletion_requests.csv');
    const canonical=x=>JSON.stringify(x,(_k,v)=>v&&typeof v==='object'&&!Array.isArray(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])):v);
    let statusCorrect=0,sequenceCorrect=0,expectedSteps=0,matchedSteps=0,fieldsCorrect=0,fieldCount=0;
    for(const expectedRow of expected){const request=requests.find(x=>x.case_id===expectedRow.case_id);if(!request)continue;
      const actual=app.analyze(request);const a=actual.steps;const e=JSON.parse(expectedRow.steps_json);
      if(actual.deletion_status===expectedRow.deletion_status)statusCorrect++;
      if(canonical(a)===canonical(e))sequenceCorrect++;
      expectedSteps+=e.length;for(let i=0;i<Math.max(a.length,e.length);i++){
        if(i<a.length&&i<e.length){if(canonical(a[i])===canonical(e[i]))matchedSteps++;for(const key of ['step_no','phase','system_id','resource_id','operation','state','evidence_id']){fieldCount++;if(a[i][key]===e[i][key])fieldsCorrect++;}}
      }
    }
    const result={sample_cases:expected.length,status_accuracy:statusCorrect/expected.length,step_sequence_accuracy:sequenceCorrect/expected.length,exact_step_fraction:expectedSteps?matchedSteps/expectedSteps:0,field_accuracy:fieldCount?fieldsCorrect/fieldCount:0,status_correct:statusCorrect,sequence_correct:sequenceCorrect,expected_step_count:expectedSteps,field_count:fieldCount,fields_correct:fieldsCorrect};
    console.log(JSON.stringify(result,null,2));
  }
  else if(process.argv.includes('--debug-sample')){
    const expected=load('sample_output.csv');const requests=load('sample_deletion_requests.csv');
    for(const e of expected){const r=requests.find(x=>x.case_id===e.case_id);const a=app.analyze(r);if(a.deletion_status!==e.deletion_status||JSON.stringify(a.steps)!==JSON.stringify(JSON.parse(e.steps_json)))console.log(JSON.stringify({case_id:e.case_id,email:r.email,expected_status:e.deletion_status,actual_status:a.deletion_status,expected_steps:JSON.parse(e.steps_json).slice(0,3),actual_steps:a.steps.slice(0,3),note:a.explanation}));}
  }
  else if(process.argv.includes('--debug-one')){
    const id=process.argv[process.argv.indexOf('--debug-one')+1];const request=app.sample.find(x=>x.case_id===id);const profile=[...app.identities.values()].find(p=>p.identifiers.has(norm(request?.email)));
    console.log(JSON.stringify({request,profile:profile&&{user_id:profile.user_id,identifiers:[...profile.identifiers]},observations:profile&&(app.observationIndex.get(profile.user_id)||[]).map(o=>({file_id:o.evidence.file_id,captured_at:o.evidence.captured_at,resource:o.resource,object:o.object})),result:request&&app.analyze(request)},null,2));
  }
  else server.listen(PORT,()=>console.log(`GHOSTPRINTS listening on http://localhost:${PORT}`));
}
module.exports={Ghostprints,csv,deletionIntent,parseSqlValues,parseSqlSchema};
