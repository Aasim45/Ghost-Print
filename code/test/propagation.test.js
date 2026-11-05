const test = require('node:test');
const assert = require('node:assert/strict');
const {
  analyzePropagation,
  aggregatePropagationStatus
} = require('../propagation');

const request = {
  case_id: 'case_test',
  requested_at: '2026-09-01T10:00:00Z',
  audit_at: '2026-09-01T12:00:00Z'
};

const profile = {
  user_id: 'user_1',
  email: 'person@example.com',
  identifiers: new Set(['user_1', 'person@example.com'])
};

const rules = [
  { data_category: 'USER_PROFILE', required_action: 'DELETE' },
  { data_category: 'SUPPORT_MESSAGE', required_action: 'REDACT' },
  { data_category: 'SECURITY_AUDIT_LOG', required_action: 'RETAIN' }
];

const systemFor = resource => resource.startsWith('account_') ? 'account_service' : resource.startsWith('support_') ? 'support_platform' : 'security_service';
const policyAction = category => rules.find(rule => rule.data_category === category)?.required_action || '';

function observation(resource_id, object, evidence_id, captured_at) {
  return {
    resource: resource_id,
    object,
    evidence: { file_id: evidence_id, captured_at }
  };
}

test('calculates independent processing and verified propagation durations', () => {
  const result = analyzePropagation({
    request,
    profile,
    observations: [
      observation('account_1', { state: 'ABSENT' }, 'evidence_account', '2026-09-01T10:40:00Z'),
      observation('support_1', { state: 'REDACTED' }, 'evidence_support', '2026-09-01T11:15:00Z')
    ],
    activities: [
      { activity_id: 'activity_account', event_time: '2026-09-01T10:02:00Z', event_type: 'DELETE_RECORD', resource_id: 'account_1', reported_result: 'SUCCESS', details: '' },
      { activity_id: 'activity_support', event_time: '2026-09-01T10:05:00Z', event_type: 'REDACT_RECORD', resource_id: 'support_1', reported_result: 'SUCCESS', details: '' }
    ],
    rules,
    systemFor,
    policyAction
  });

  assert.equal(result.case_status, 'COMPLETE');
  assert.equal(result.processing_delay_ms, 120000);
  assert.equal(result.verified_propagation_ms, 4500000);
  assert.equal(result.resources.find(r => r.resource_id === 'account_1').processing_delay_ms, 120000);
  assert.equal(result.resources.find(r => r.resource_id === 'support_1').processing_delay_ms, 300000);
});

test('ignores events and evidence after audit_at and keeps pending separate', () => {
  const result = analyzePropagation({
    request,
    profile,
    observations: [
      observation('account_1', { state: 'ABSENT' }, 'future_evidence', '2026-09-01T12:01:00Z')
    ],
    activities: [
      { activity_id: 'future_activity', event_time: '2026-09-01T12:01:00Z', event_type: 'DELETE_RECORD', resource_id: 'account_1', reported_result: 'SUCCESS', details: '' }
    ],
    rules,
    systemFor,
    policyAction
  });

  assert.equal(result.case_status, 'UNKNOWN');
  assert.equal(result.resources.length, 0);
  assert.equal(result.verified_completion_at, null);
});

test('successful activity without verification is unknown, not complete', () => {
  const result = analyzePropagation({
    request,
    profile,
    observations: [],
    activities: [
      { activity_id: 'activity_success', event_time: '2026-09-01T10:05:00Z', event_type: 'DELETE_RECORD', resource_id: 'account_1', reported_result: 'SUCCESS', details: 'person@example.com' }
    ],
    rules,
    systemFor,
    policyAction
  });

  assert.equal(result.case_status, 'UNKNOWN');
  assert.equal(result.resources[0].state, 'UNKNOWN_UNVERIFIED');
  assert.equal(result.resources[0].pending_duration_ms, 6900000);
});

test('retention pending is distinct from failed cleanup', () => {
  const result = analyzePropagation({
    request,
    profile,
    observations: [
      observation('audit_record_1', { retention_until: '2026-12-01T00:00:00Z' }, 'evidence_retention', '2026-09-01T10:10:00Z')
    ],
    activities: [
      { activity_id: 'activity_retention', event_time: '2026-09-01T10:05:00Z', event_type: 'RETAIN_RECORD', resource_id: 'audit_record_1', reported_result: 'SUCCESS', details: 'person@example.com' }
    ],
    rules: [...rules, { data_category: 'SECURITY_AUDIT_LOG', required_action: 'RETAIN' }],
    systemFor: () => 'security_service',
    policyAction: () => 'RETAIN'
  });

  assert.equal(result.case_status, 'RETENTION_PENDING');
  assert.equal(result.resources[0].state, 'RETENTION_PENDING');
});

test('empty resources aggregate to UNKNOWN', () => {
  assert.equal(aggregatePropagationStatus([]), 'UNKNOWN');
  assert.equal(aggregatePropagationStatus(null), 'UNKNOWN');
});

test('failed cleanup does not become complete', () => {
  assert.equal(aggregatePropagationStatus([{ state: 'DELETED_VERIFIED' }, { state: 'FAILED' }]), 'FAILED');
  assert.equal(aggregatePropagationStatus([{ state: 'DELETED_VERIFIED' }, { state: 'PENDING' }]), 'PENDING');
});

test('terminal evidence conflicts with a failed activity instead of becoming complete', () => {
  const result = analyzePropagation({
    request,
    profile,
    observations: [observation('account_1', { state: 'ABSENT' }, 'evidence_account', '2026-09-01T10:40:00Z')],
    activities: [{ activity_id: 'activity_failed', event_time: '2026-09-01T10:05:00Z', event_type: 'DELETE_RECORD', resource_id: 'account_1', reported_result: 'PARTIAL', details: 'person@example.com' }],
    rules,
    systemFor,
    policyAction
  });
  assert.equal(result.case_status, 'UNKNOWN');
  assert.equal(result.resources[0].state, 'CONFLICTING');
});
