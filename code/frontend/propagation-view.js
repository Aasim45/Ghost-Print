(function(root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.GhostprintsPropagationView = factory();
}(typeof globalThis === 'object' ? globalThis : this, function() {
  function timestamp(value) {
    const parsed = Date.parse(value || '');
    return Number.isFinite(parsed) ? parsed : null;
  }
  function elapsedMs(start, end) {
    const from = timestamp(start); const to = timestamp(end);
    return from === null || to === null || to < from ? null : to - from;
  }
  function formatDuration(ms) {
    if (ms === null || ms === undefined) return 'Unavailable';
    const seconds = Math.round(ms / 1000);
    const hours = Math.floor(seconds / 3600); const minutes = Math.floor((seconds % 3600) / 60); const rest = seconds % 60;
    return [hours ? `${hours}h` : null, minutes ? `${minutes}m` : null, `${rest}s`].filter(Boolean).join(' ');
  }
  function uniqueResources(records) {
    const unique = new Map();
    for (const record of records || []) for (const resource of record.propagation?.resources || []) {
      const key = `${record.case_id}/${resource.system_id}/${resource.resource_id}`;
      if (!unique.has(key)) unique.set(key, { ...resource, case_id: record.case_id });
    }
    return [...unique.values()];
  }
  function processingMs(record) { return elapsedMs(record?.request?.requested_at, record?.propagation?.processing_start_at); }
  function verifiedPropagationMs(propagation) { return elapsedMs(propagation?.processing_start_at, propagation?.verified_completion_at); }
  function pendingMs(resource, propagation) {
    if (!['PENDING', 'FAILED'].includes(resource?.state)) return null;
    return elapsedMs(resource.processing_start_at, propagation?.audit_at);
  }
  function resourceCategory(resource) {
    const state = resource?.state || 'UNKNOWN_UNVERIFIED';
    if (state === 'DELETED_VERIFIED' || state === 'REDACTED_VERIFIED' || state === 'ANONYMIZED_VERIFIED' || state === 'RETAINED_VERIFIED') return 'VERIFIED';
    if (state === 'CONFLICTING') return 'CONFLICTING';
    if (state === 'FAILED') return 'FAILED';
    if (state === 'PENDING') return 'PENDING';
    if (state === 'RETENTION_PENDING') return 'RETENTION_PENDING';
    if (resource?.unreadable_evidence_ids?.length) return 'UNREADABLE_EVIDENCE';
    if (resource?.post_cutoff_evidence_ids?.length || resource?.post_cutoff_activity_ids?.length) return 'AFTER_CUTOFF';
    if (resource?.evidence_ids?.length) return 'EVIDENCE_UNVERIFIED';
    if (resource?.activity_ids?.length) return 'ACTIVITY_UNVERIFIED';
    return 'UNKNOWN';
  }
  function resourceCategoryLabel(resource) {
    return ({ VERIFIED: 'Verified terminal state', CONFLICTING: 'Conflicting signals', FAILED: 'Cleanup failed', PENDING: 'Cleanup pending', RETENTION_PENDING: 'Retention pending', UNREADABLE_EVIDENCE: 'Unreadable evidence', AFTER_CUTOFF: 'Evidence after cutoff', EVIDENCE_UNVERIFIED: 'Evidence supplied; state unverified', ACTIVITY_UNVERIFIED: 'Activity claim; state unverified', UNKNOWN: 'Unknown verification' })[resourceCategory(resource)];
  }
  function stateCounts(resources) {
    return (resources || []).reduce((counts, resource) => {
      const category = resourceCategory(resource);
      counts[category] = (counts[category] || 0) + 1;
      return counts;
    }, {});
  }
  function summarize(records) {
    const resources = uniqueResources(records); const pending = resources.filter(resource => pendingMs(resource, records.find(record => record.case_id === resource.case_id)?.propagation) !== null);
    return {
      matching_cases: new Set((records || []).map(record => record.case_id)).size,
      resources_checked: resources.length,
      unknown_or_unverified: resources.filter(resource => /UNKNOWN|UNVERIFIED/.test(resource.state || '')).length,
      pending_cleanup: pending.length
    };
  }
  return { elapsedMs, formatDuration, uniqueResources, processingMs, verifiedPropagationMs, pendingMs, resourceCategory, resourceCategoryLabel, stateCounts, summarize };
}));
