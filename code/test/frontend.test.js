const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const frontend = fs.readFileSync(path.join(__dirname, '..', 'frontend', 'app.js'), 'utf8');
const index = fs.readFileSync(path.join(__dirname, '..', 'frontend', 'index.html'), 'utf8');
const view = require('../frontend/propagation-view');

test('sidebar routes investigations and persistent checker separately', () => {
  assert.match(index, /href="#investigations" data-view="investigations"/);
  assert.match(index, /href="#persistent-deletion-checker" data-view="persistent-deletion-checker"/);
  assert.match(frontend, /async function persistentDeletionChecker\(\)/);
  assert.match(frontend, /persistent-deletion-checker/);
  assert.match(frontend, /api\('\/api\/investigations\?/);
  assert.match(frontend, /\/propagation/);
});

test('persistent checker renders propagation fields and remains distinct from investigations', () => {
  assert.match(frontend, /Deletion Propagation Dashboard/);
  assert.match(frontend, /Audit cutoff/);
  assert.match(frontend, /Request → processing/);
  assert.match(frontend, /Verified propagation/);
  assert.match(frontend, /Pending cleanup/);
  assert.match(frontend, /Evidence:/);
  assert.doesNotMatch(frontend, /persistent-deletion-checker.*investigations/);
});

test('propagation durations reject missing, invalid, and reversed timestamps but allow genuine zero', () => {
  assert.equal(view.processingMs({ request: { requested_at: '2026-09-01T10:00:00Z' }, propagation: { processing_start_at: null } }), null);
  assert.equal(view.processingMs({ request: { requested_at: 'not-a-date' }, propagation: { processing_start_at: '2026-09-01T10:00:00Z' } }), null);
  assert.equal(view.processingMs({ request: { requested_at: '2026-09-01T10:01:00Z' }, propagation: { processing_start_at: '2026-09-01T10:00:00Z' } }), null);
  assert.equal(view.processingMs({ request: { requested_at: '2026-09-01T10:00:00Z' }, propagation: { processing_start_at: '2026-09-01T10:00:00Z' } }), 0);
  assert.equal(view.formatDuration(null), 'Unavailable');
  assert.equal(view.formatDuration(0), '0s');
});

test('propagation aggregation deduplicates resources and preserves mixed states', () => {
  const longResource = 'resource_with_a_very_long_identifier_that_must_wrap_without_clipping_123456789';
  const records = [{ case_id: 'case_34', request: { requested_at: '2026-09-24T08:00:00Z' }, propagation: {
    audit_at: '2026-09-27T13:00:00Z', processing_start_at: '2026-08-28T12:46:35Z',
    resources: [
      { system_id: 'service_with_a_long_system_identifier', resource_id: longResource, state: 'UNKNOWN_UNVERIFIED', processing_start_at: null },
      { system_id: 'support_platform', resource_id: 'support_9538', state: 'FAILED', processing_start_at: '2026-08-28T12:46:35Z' },
      { system_id: 'support_platform', resource_id: 'support_9538', state: 'FAILED', processing_start_at: '2026-08-28T12:46:35Z' }
    ]
  }}];
  assert.equal(view.uniqueResources(records).length, 2);
  assert.deepEqual(view.summarize(records), { matching_cases: 1, resources_checked: 2, unknown_or_unverified: 1, pending_cleanup: 1 });
  assert.equal(view.pendingMs(records[0].propagation.resources[0], records[0].propagation), null);
  assert.equal(view.pendingMs(records[0].propagation.resources[1], records[0].propagation), 2592805000);
  assert.match(frontend, /resource-references/);
  assert.match(frontend, /resource-timing/);
});

test('propagation dashboard keeps unknown diagnostics readable and compact', () => {
  assert.match(frontend, /persistentDeletionCheckerRefined/);
  assert.match(frontend, /propagation-details/);
  assert.match(frontend, /Unknown means the supplied data does not prove a terminal state/);
  assert.match(frontend, /Showing \$\{records.length\} of \$\{summary.matching_cases\}/);
  assert.match(frontend, /limit:q\?25:10/);
});

test('resource diagnostic categories distinguish verified, failed, unreadable, and unknown states', () => {
  assert.equal(view.resourceCategory({ state: 'DELETED_VERIFIED' }), 'VERIFIED');
  assert.equal(view.resourceCategory({ state: 'FAILED' }), 'FAILED');
  assert.equal(view.resourceCategory({ state: 'UNKNOWN_UNVERIFIED', unreadable_evidence_ids: ['evidence_04'] }), 'UNREADABLE_EVIDENCE');
  assert.equal(view.resourceCategory({ state: 'UNKNOWN_UNVERIFIED', evidence_ids: ['evidence_01'] }), 'EVIDENCE_UNVERIFIED');
  assert.equal(view.resourceCategory({ state: 'UNKNOWN_UNVERIFIED', activity_ids: ['activity_1'] }), 'ACTIVITY_UNVERIFIED');
  assert.equal(view.resourceCategory({ state: 'UNKNOWN_UNVERIFIED' }), 'UNKNOWN');
  assert.deepEqual(view.stateCounts([{ state: 'FAILED' }, { state: 'UNKNOWN_UNVERIFIED' }, { state: 'UNKNOWN_UNVERIFIED', evidence_ids: ['e'] }]), { FAILED: 1, UNKNOWN: 1, EVIDENCE_UNVERIFIED: 1 });
});
