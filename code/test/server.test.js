const test = require('node:test');
const assert = require('node:assert/strict');
const { csv, deletionIntent, Ghostprints } = require('../server');

test('CSV parser handles quoted commas and escaped quotes', () => {
  const rows = csv('case_id,request_text\ncase_1,"Please delete, erase, and say ""done""."\n');
  assert.deepEqual(rows, [{ case_id:'case_1', request_text:'Please delete, erase, and say "done".' }]);
});

test('deletion intent accepts clear delete language', () => {
  assert.equal(deletionIntent('Please erase my account and delete associated personal data.'), true);
  assert.equal(deletionIntent('Quiero eliminar mi cuenta.'), true);
  assert.equal(deletionIntent('Solicito a exclusão permanente da conta associada a este e-mail.'), true);
  assert.equal(deletionIntent('계정의 영구 삭제를 요청합니다.'), true);
  assert.equal(deletionIntent('このアカウントを削除してください。'), true);
});

test('non-deletion requests are not treated as deletion', () => {
  assert.equal(deletionIntent('Please export my account data.'), false);
  assert.equal(deletionIntent('Update my account email; do not delete it.'), false);
  assert.equal(deletionIntent('Please unsubscribe me from marketing.'), false);
  assert.equal(deletionIntent('What is the deletion policy?'), false);
  assert.equal(deletionIntent('Please export my data and keep my account active.'), false);
});

test('case_54 Portuguese deletion request is applicable', () => {
  const app = new Ghostprints();
  const request = app.requests.find(item => item.case_id === 'case_54');
  const result = app.analyze(request);
  assert.equal(deletionIntent(request.request_text), true);
  assert.notEqual(result.deletion_status, 'NOT_APPLICABLE');
  assert.ok(result.steps.some(step => step.resource_id === 'analytics_1738'));
});

test('incomplete results expose structured reasons without changing output steps', () => {
  const app = new (require('../server').Ghostprints)();
  const result = app.resultFor(app.requests.find(request => request.case_id === 'case_34'));
  assert.equal(result.deletion_status, 'INCOMPLETE');
  assert.ok(result.reasons.length >= 1);
  assert.ok(result.reasons.every(reason => reason.code && reason.title && reason.explanation && reason.next_action));
  assert.ok(result.reasons.some(reason => reason.evidence_ids.includes('evidence_01')));
});

test('case_33 generates incomplete investigation tasks for known resources', () => {
  const app = new Ghostprints();
  const result = app.resultFor(app.requests.find(request => request.case_id === 'case_33'));
  assert.equal(result.deletion_status, 'INCOMPLETE');
  assert.equal(result.steps.length, 2);
  assert.equal(result.investigation_state, 'INVESTIGATION_REQUIRED_NOT_PERFORMED');
  assert.ok(result.steps.every(step => step.phase === 'VERIFICATION' && step.evidence_id === ''));
  assert.ok(result.steps.every(step => ['export_1260', 'export_1842'].includes(step.resource_id)));
  assert.equal(result.pipeline_trace.identity_matching.status, 'RESOLVED');
  assert.equal(result.pipeline_trace.policy_evaluation.resources.length, 2);
  assert.equal(result.pipeline_trace.step_generation.zero_steps, false);
  assert.ok(result.reasons.some(reason => reason.activity_ids.includes('activity_4004')));
  assert.ok(result.reasons.every(reason => reason.expected && reason.observed && reason.prevents_verification));
});

test('case_57 explains why zero steps are appropriate when no resources are attributable', () => {
  const app = new Ghostprints();
  const result = app.resultFor(app.requests.find(request => request.case_id === 'case_57'));
  assert.equal(result.deletion_status, 'INCOMPLETE');
  assert.equal(result.steps.length, 0);
  assert.equal(result.investigation_state, 'INVESTIGATION_REQUIRED_NO_ATTRIBUTABLE_RESOURCES');
  assert.match(result.investigation_explanation, /Insufficient attributable resource data/);
});

test('not-applicable requests require no investigation', () => {
  const app = new Ghostprints();
  for (const caseId of ['case_533', 'case_535', 'case_536', 'case_537', 'case_540', 'case_541', 'case_542']) {
    const result = app.resultFor(app.requests.find(request => request.case_id === caseId));
    assert.equal(result.deletion_status, 'NOT_APPLICABLE');
    assert.equal(result.steps.length, 0);
    assert.equal(result.investigation_state, 'NO_INVESTIGATION_REQUIRED');
  }
});

test('reason coverage reports incomplete cases and zero-step cases without changing output schema', () => {
  const app = new (require('../server').Ghostprints)();
  const coverage = app.reasonCoverage();
  assert.equal(coverage.total_incomplete_cases, 510);
  assert.equal(coverage.total_cases, 518);
  assert.ok(coverage.cases_with_detailed_reasons > 0);
  assert.equal(coverage.cases_with_generic_reasons, coverage.cases_with_unknown_causes);
  assert.equal(coverage.cases_with_no_reasons, 0);
  assert.ok(coverage.cases_with_zero_investigation_steps > 0);
  assert.ok(coverage.cases_receiving_generated_investigation_tasks > 0);
  assert.ok(coverage.cases_with_zero_steps_appropriate > 0);
  assert.ok(coverage.most_frequent_root_causes.length > 0);
  assert.deepEqual(Object.keys(JSON.parse(JSON.stringify({ case_id: 'x', deletion_status: 'INCOMPLETE', steps_json: '[]' }))), ['case_id', 'deletion_status', 'steps_json']);
});

test('propagation summary aggregates unique case resources and justified pending states', () => {
  const app = new Ghostprints();
  assert.deepEqual(app.propagationSummary('case_34'), {
    matching_cases: 1,
    resources_checked: 6,
    unknown_or_unverified: 5,
    pending_cleanup: 1,
    state_counts: { UNKNOWN_UNVERIFIED: 5, FAILED: 1 },
    verified_resources: 0,
    failed_resources: 1,
    pending_resources: 0,
    conflicting_resources: 0
  });
});

test('does not promote unresolved cases to COMPLETE', () => {
  const app = new (require('../server').Ghostprints)();
  const results = app.all();
  assert.equal(results.filter(result => result.deletion_status === 'COMPLETE').length, 1);
  assert.equal(results.find(result => result.case_id === 'case_33').deletion_status, 'INCOMPLETE');
  for (const result of results.filter(item => item.deletion_status === 'COMPLETE')) {
    assert.ok(result.steps.length > 0);
    assert.ok(result.steps.every(step => step.phase === 'VERIFICATION' && step.evidence_id));
  }
});

