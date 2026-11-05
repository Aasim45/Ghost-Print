const test = require('node:test');
const assert = require('node:assert/strict');
const { buildAuditReasons } = require('../reasons');

const request = { audit_at: '2026-09-01T12:00:00Z' };
const base = { deletion_status: 'INCOMPLETE', steps: [] };

test('generates multiple case-specific reasons from findings', () => {
  const reasons = buildAuditReasons({
    request, result: { ...base, steps: [
      { phase: 'FINDING', operation: 'REPORT_REMAINING_RECORD', state: 'PRESENT', system_id: 'search_service', resource_id: 'search_1', evidence_id: 'evidence_1' },
      { phase: 'FINDING', operation: 'REPORT_ACTIVE_DATA_FLOW', state: 'ACTIVE', system_id: 'integration_service', resource_id: 'data_flow_1', evidence_id: 'evidence_2' }
    ] }, propagation: { resources: [] }
  });
  assert.equal(reasons.length, 2);
  assert.deepEqual(reasons.map(reason => reason.code), ['RESIDUAL_DATA_FOUND', 'ACTIVE_DATA_FLOW']);
  assert.equal(reasons[0].evidence_ids[0], 'evidence_1');
  assert.match(reasons[1].next_action, /Disable/);
});

test('reports missing evidence without claiming the record was deleted', () => {
  const reasons = buildAuditReasons({
    request, result: base, propagation: { resources: [{ system_id: 'account_service', resource_id: 'account_1', state: 'UNKNOWN_UNVERIFIED', evidence_ids: [], activity_ids: ['activity_1'] }] }
  });
  assert.equal(reasons[0].code, 'EVIDENCE_NOT_SUPPLIED');
  assert.equal(reasons[0].classification, 'UNKNOWN');
  assert.match(reasons[0].explanation, /no participant-visible evidence/i);
  assert.deepEqual(reasons[0].evidence_ids, []);
});

test('uses an explicit unknown-cause reason when no signal can be attributed', () => {
  const reasons = buildAuditReasons({ request, result: base, propagation: { resources: [], errors: [] } });
  assert.equal(reasons.length, 1);
  assert.equal(reasons[0].code, 'UNKNOWN_CAUSE');
  assert.equal(reasons[0].title, 'Reason could not be determined from available data.');
});

test('distinguishes pending cleanup from unknown verification', () => {
  const reasons = buildAuditReasons({
    request, result: base, propagation: { resources: [
      { system_id: 'search_service', resource_id: 'search_1', state: 'PENDING', evidence_ids: ['evidence_1'], activity_ids: [] },
      { system_id: 'support_platform', resource_id: 'support_1', state: 'UNKNOWN_UNVERIFIED', evidence_ids: ['evidence_2'], activity_ids: [] }
    ] }
  });
  assert.deepEqual(reasons.map(reason => reason.code), ['CLEANUP_PENDING', 'INSUFFICIENT_TERMINAL_EVIDENCE']);
  assert.equal(reasons[0].classification, 'PENDING');
  assert.equal(reasons[1].classification, 'UNKNOWN');
});

test('classifies cutoff, unreadable, unlinked, missing activity, and terminal-state failures with structured fields', () => {
  const cases = [
    ['EVIDENCE_AFTER_CUTOFF', { state: 'UNKNOWN_UNVERIFIED', post_cutoff_evidence_ids: ['late_1'], activity_ids: ['activity_1'] }],
    ['UNREADABLE_EVIDENCE', { state: 'UNKNOWN_UNVERIFIED', unreadable_evidence_ids: ['image_1'], activity_ids: ['activity_1'] }],
    ['EVIDENCE_NOT_LINKED', { state: 'UNKNOWN_UNVERIFIED', evidence_supplied_elsewhere: true, activity_ids: ['activity_1'] }],
    ['MISSING_ACTIVITY', { state: 'UNKNOWN_UNVERIFIED', evidence_ids: [], activity_ids: [] }],
    ['INSUFFICIENT_TERMINAL_EVIDENCE', { state: 'UNKNOWN_UNVERIFIED', evidence_ids: ['evidence_1'], activity_ids: ['activity_1'] }]
  ];
  for (const [rootCause, resource] of cases) {
    const reason = buildAuditReasons({ request, result: base, propagation: { resources: [{ system_id: 'export_service', resource_id: 'export_1', ...resource }] }, activities: [] })[0];
    assert.equal(reason.root_cause || reason.code, rootCause);
    for (const field of ['expected', 'observed', 'missing_or_conflicting', 'prevents_verification', 'next_action']) assert.ok(reason[field], field);
    assert.equal(reason.system_id, 'export_service');
    assert.equal(reason.resource_id, 'export_1');
  }
});

test('deduplicates one root cause while retaining affected resource details', () => {
  const reasons = buildAuditReasons({
    request, result: base, propagation: { resources: [
      { system_id: 'export_service', resource_id: 'export_1', state: 'UNKNOWN_UNVERIFIED', activity_ids: ['activity_1'] },
      { system_id: 'export_service', resource_id: 'export_2', state: 'UNKNOWN_UNVERIFIED', activity_ids: ['activity_2'] }
    ] }
  });
  assert.equal(reasons.length, 1);
  assert.deepEqual(reasons[0].resource_ids.sort(), ['export_1', 'export_2']);
  assert.deepEqual(reasons[0].activity_ids.sort(), ['activity_1', 'activity_2']);
});

test('supports every requested reason category without inventing evidence', () => {
  const reason = (result, propagation = { resources: [] }) => buildAuditReasons({ request, result: { ...base, ...result }, propagation });
  const codes = new Set();
  for (const operation of ['REPORT_REMAINING_RECORD', 'REPORT_ACTIVE_DATA_FLOW', 'REPORT_RESTORE_RISK']) {
    codes.add(reason({ steps: [{ phase: 'FINDING', operation, state: operation === 'REPORT_REMAINING_RECORD' ? 'PRESENT' : 'ACTIVE', system_id: 'service', resource_id: 'resource_1', evidence_id: 'evidence_1' }] })[0].code);
  }
  const resources = [
    { state: 'FAILED', resource_id: 'r1' },
    { state: 'RETENTION_PENDING', resource_id: 'r2' },
    { state: 'CONFLICTING', resource_id: 'r3' },
    { state: 'UNKNOWN_UNVERIFIED', resource_id: 'r4', post_cutoff_evidence_ids: ['late'] },
    { state: 'UNKNOWN_UNVERIFIED', resource_id: 'r5', unreadable_evidence_ids: ['image'] },
    { state: 'UNKNOWN_UNVERIFIED', resource_id: 'r6', evidence_supplied_elsewhere: true, activity_ids: ['a6'] },
    { state: 'UNKNOWN_UNVERIFIED', resource_id: 'r7', evidence_ids: ['e7'], activity_ids: ['a7'] },
    { state: 'UNKNOWN_UNVERIFIED', resource_id: 'r8', activity_ids: [] },
    { state: 'UNKNOWN_UNVERIFIED', resource_id: 'r9', activity_ids: ['a9'] }
  ];
  const resourcesReasons = buildAuditReasons({ request, result: base, propagation: { resources }, activities: [] });
  for (const item of resourcesReasons) codes.add(item.code);
  codes.add(reason({}, { errors: [{ code: 'IDENTITY_NOT_FOUND', message: 'No unique identity profile was resolved.' }] })[0].code);
  codes.add(reason({}, { resources: [], errors: [] })[0].code);
  assert.deepEqual([...codes].sort(), [
    'ACTIVE_DATA_FLOW', 'CLEANUP_PENDING', 'CONFLICTING_EVIDENCE', 'EVIDENCE_AFTER_CUTOFF', 'EVIDENCE_NOT_LINKED',
    'EVIDENCE_NOT_SUPPLIED', 'IDENTITY_MATCH_FAILED', 'INCOMPLETE_WORKFLOW', 'INSUFFICIENT_TERMINAL_EVIDENCE',
    'MISSING_ACTIVITY', 'RESIDUAL_DATA_FOUND', 'RETENTION_PENDING', 'UNKNOWN_CAUSE', 'UNREADABLE_EVIDENCE'
  ].sort());
});
