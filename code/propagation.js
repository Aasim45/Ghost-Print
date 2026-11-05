'use strict';

const CLEANUP_EVENTS = new Set([
  'DELETE_RECORD',
  'REDACT_RECORD',
  'ANONYMIZE_RECORD',
  'DISABLE_DATA_FLOW',
  'BLOCK_RESTORE',
  'RETAIN_RECORD'
]);

const VERIFIED_STATES = new Set([
  'DELETED_VERIFIED',
  'REDACTED_VERIFIED',
  'ANONYMIZED_VERIFIED',
  'RETAINED_VERIFIED'
]);

const RESOURCE_STATES = new Set([
  ...VERIFIED_STATES,
  'PENDING',
  'FAILED',
  'RETENTION_PENDING',
  'UNKNOWN_UNVERIFIED'
]);

function text(value) {
  return String(value ?? '');
}

function norm(value) {
  return text(value).trim().toLocaleLowerCase('en-US');
}

function timestamp(value) {
  const parsed = Date.parse(value || '');
  return Number.isFinite(parsed) ? parsed : null;
}

function iso(value) {
  const parsed = timestamp(value);
  return parsed === null ? null : new Date(parsed).toISOString();
}

function duration(start, end) {
  const a = timestamp(start);
  const b = timestamp(end);
  return a === null || b === null ? null : Math.max(0, b - a);
}

function flatValues(value, output = []) {
  if (!value || typeof value !== 'object') return output;
  for (const [key, child] of Object.entries(value)) {
    if (child && typeof child === 'object') flatValues(child, output);
    else if (child !== null && child !== undefined) output.push([key, text(child)]);
  }
  return output;
}

function encodedObservation(observation) {
  return JSON.stringify(observation?.object ?? observation ?? {});
}

function identifiersFor(profile) {
  const values = new Set();
  for (const value of profile?.identifiers || []) values.add(norm(value));
  for (const value of [profile?.user_id, profile?.email, profile?.email_hash, profile?.phone, profile?.name]) {
    if (value) values.add(norm(value));
  }
  values.delete('');
  return values;
}

function activityMatchesIdentity(activity, profile, resourceIds) {
  if (!activity || !activity.resource_id) return false;
  if (resourceIds.has(text(activity.resource_id))) return true;
  const details = norm(activity.details);
  return [...identifiersFor(profile)].some(identifier => identifier && details.includes(identifier));
}

function inferCategory(resource, object) {
  const explicit = text(object?.data_category || object?.category).toUpperCase();
  if (explicit) return explicit;
  const collection = norm(object?.collection_name);
  const name = norm(resource);
  if (collection.includes('customer_profiles') || name.startsWith('account_')) return 'USER_PROFILE';
  if (collection.includes('search') || name.startsWith('search_')) return 'SEARCH_INDEX_ENTRY';
  if (collection.includes('analytics') || name.startsWith('analytics_')) return 'ANALYTICS_PROFILE';
  if (collection.includes('telemetry') || name.startsWith('telemetry_')) return 'PRODUCT_TELEMETRY';
  if (collection.includes('support') && collection.includes('attachment')) return 'SUPPORT_ATTACHMENT';
  if (collection.includes('support') || name.startsWith('support_')) return 'SUPPORT_MESSAGE';
  if (collection.includes('export') || name.startsWith('export_')) return 'USER_EXPORT';
  if (collection.includes('backup') || collection.includes('archive') || name.startsWith('backup_') || name.startsWith('archive_')) return 'BACKUP_ARCHIVE';
  if (collection.includes('audit') || name.startsWith('audit_record_')) return 'SECURITY_AUDIT_LOG';
  if (name.startsWith('tombstone_')) return 'ACCOUNT_TOMBSTONE';
  return '';
}

function ruleFor(rules, category, policyAction) {
  const matching = (rules || []).find(rule => norm(rule.data_category) === norm(category));
  const action = matching?.required_action || (policyAction ? policyAction(category) : '');
  return { rule: matching || null, action: text(action).toUpperCase() };
}

function explicitEvidenceTimestamp(observation) {
  const object = observation?.object || {};
  for (const key of ['verified_at', 'completed_at', 'observed_at', 'recorded_at', 'updated_at', 'event_time']) {
    const value = object[key];
    if (timestamp(value) !== null) return iso(value);
  }
  return iso(observation?.evidence?.captured_at);
}

function evidenceTimestamps(observations, cutoff) {
  return observations
    .map(observation => ({
      evidence_id: observation?.evidence?.file_id,
      captured_at: iso(observation?.evidence?.captured_at),
      state_at: explicitEvidenceTimestamp(observation)
    }))
    .filter(item => item.evidence_id && item.captured_at && timestamp(item.captured_at) <= cutoff);
}

function hasIdentifier(object, profile) {
  const identifiers = identifiersFor(profile);
  return flatValues(object).some(([, value]) => identifiers.has(norm(value)));
}

function provesAbsent(encoded) {
  return /NOT_FOUND|NO_RECORD|"deleted"\s*:\s*true|"state"\s*:\s*"(?:ABSENT|DELETED)"|rows?\s*[:=]\s*0/i.test(encoded);
}

function provesAnonymized(encoded, object, profile) {
  return /ANONYMIZED|"anonymized"\s*:\s*true|"subject_reference"\s*:\s*null/i.test(encoded) && !hasIdentifier(object, profile);
}

function provesRedacted(encoded, object, profile) {
  const tombstone = /tombstone|ACCOUNT_TOMBSTONE/i.test(encoded);
  const redacted = /REDACTED|"redacted"\s*:\s*true/i.test(encoded);
  return (tombstone || redacted) && !hasIdentifier(object, profile);
}

function provesRetained(object, encoded) {
  return Boolean(object) && !/"deleted"\s*:\s*true|NOT_FOUND/i.test(encoded);
}

function retentionIsPending(object, auditAt) {
  for (const key of ['retention_until', 'retained_until', 'expires_at']) {
    const value = timestamp(object?.[key]);
    if (value !== null && value > auditAt) return true;
  }
  return false;
}

function relevantActivityEvents(activities, profile, resourceIds, resourceId, cutoff) {
  return (activities || [])
    .filter(activity => timestamp(activity.event_time) !== null && timestamp(activity.event_time) <= cutoff)
    .filter(activity => text(activity.resource_id) === resourceId)
    .filter(activity => activityMatchesIdentity(activity, profile, resourceIds));
}

function terminalEvidenceFor(action, observations, profile) {
  const matches = [];
  for (const observation of observations) {
    const object = observation.object || {};
    const encoded = encodedObservation(observation);
    const verified = action === 'DELETE'
      ? provesAbsent(encoded)
      : action === 'REDACT'
        ? provesRedacted(encoded, object, profile)
        : action === 'ANONYMIZE'
          ? provesAnonymized(encoded, object, profile)
          : action === 'RETAIN'
            ? provesRetained(object, encoded)
            : /enabled\s*[=:]\s*(?:false|"false")|restore_allowed\s*[=:]\s*(?:false|"false")|DISABLED|BLOCKED/i.test(encoded);
    if (verified) matches.push(observation);
  }
  return matches;
}

function stateForAction(action) {
  if (action === 'DELETE') return 'DELETED_VERIFIED';
  if (action === 'REDACT') return 'REDACTED_VERIFIED';
  if (action === 'ANONYMIZE') return 'ANONYMIZED_VERIFIED';
  if (action === 'RETAIN') return 'RETAINED_VERIFIED';
  return 'DELETED_VERIFIED';
}

function calculateResourcePropagation({
  request,
  profile,
  observation,
  outOfCutoffObservations = [],
  activities,
  outOfCutoffActivities = [],
  rule,
  systemFor,
  policyAction
}) {
  const cutoff = timestamp(request?.audit_at);
  if (cutoff === null) throw new TypeError('request.audit_at must be a valid ISO timestamp');

  const resourceId = text(observation?.resource || activities?.find(activity => activity.resource_id)?.resource_id);
  const object = observation?.object || {};
  const category = inferCategory(resourceId, object);
  const selected = rule || ruleFor([], category, policyAction).rule;
  const action = text(selected?.required_action || policyAction?.(category)).toUpperCase();
  const systemId = systemFor ? systemFor(resourceId, encodedObservation(observation)) : 'unknown';
  const resourceIds = new Set([resourceId]);
  const events = relevantActivityEvents(activities, profile, resourceIds, resourceId, cutoff);
  const starts = events
    .filter(event => CLEANUP_EVENTS.has(text(event.event_type).toUpperCase()))
    .map(event => iso(event.event_time))
    .filter(Boolean)
    .sort();
  const processingStartAt = starts[0] || null;
  const observationsAtCutoff = observation && timestamp(observation.evidence?.captured_at) <= cutoff ? [observation] : [];
  const evidenceTimes = evidenceTimestamps(observationsAtCutoff, cutoff);
  const terminal = terminalEvidenceFor(action, observationsAtCutoff, profile);
  const failures = events.filter(event => ['FAILED', 'PARTIAL'].includes(text(event.reported_result).toUpperCase()));
  const hasRetention = action === 'RETAIN';
  let state = 'UNKNOWN_UNVERIFIED';
  let explanation = 'No sufficient evidence established the resource state by audit_at.';
  let verifiedCompletionAt = null;

  if (terminal.length && failures.length) {
    state = 'CONFLICTING';
    explanation = 'Terminal evidence conflicts with a FAILED or PARTIAL cleanup activity.';
  } else if (hasRetention && terminal.length) {
    const activeRetention = terminal.some(item => retentionIsPending(item.object, cutoff));
    state = activeRetention ? 'RETENTION_PENDING' : 'RETAINED_VERIFIED';
    verifiedCompletionAt = activeRetention ? null : evidenceTimes.map(item => item.state_at).filter(Boolean).sort().at(-1) || null;
    explanation = activeRetention
      ? 'The record is present and must remain available until its retention period ends.'
      : 'The policy-required retained record is present in evidence.';
  } else if (terminal.length) {
    state = stateForAction(action);
    verifiedCompletionAt = evidenceTimes.map(item => item.state_at).filter(Boolean).sort().at(-1) || null;
    explanation = 'Independent evidence proves the policy-required terminal state.';
  } else if (failures.length) {
    state = hasRetention ? 'RETENTION_PENDING' : 'FAILED';
    explanation = hasRetention
      ? 'Retention remains required and the available retention evidence is incomplete.'
      : 'A cleanup activity reported FAILED or PARTIAL and no terminal evidence was found.';
  } else if (processingStartAt && observationsAtCutoff.length) {
    state = hasRetention ? 'RETENTION_PENDING' : 'PENDING';
    explanation = hasRetention
      ? 'The record is subject to retention and has not reached a verified retention state.'
      : 'Processing started, but no independent terminal evidence was found by audit_at.';
  }

  const requestedAt = iso(request.requested_at);
  const resource = {
    system_id: systemId || 'unknown',
    resource_id: resourceId || 'unknown',
    data_category: category,
    required_action: action,
    state,
    processing_start_at: processingStartAt,
    processing_delay_ms: duration(requestedAt, processingStartAt),
    verified_completion_at: verifiedCompletionAt,
    propagation_ms: duration(requestedAt, verifiedCompletionAt),
    pending_duration_ms: !verifiedCompletionAt && processingStartAt
      ? duration(processingStartAt, request.audit_at)
      : null,
    evidence_ids: evidenceTimes.map(item => item.evidence_id),
    evidence_timestamps: evidenceTimes,
    post_cutoff_evidence_ids: outOfCutoffObservations.map(item => item?.evidence?.file_id).filter(Boolean),
    activity_ids: events.map(event => event.activity_id).filter(Boolean),
    post_cutoff_activity_ids: outOfCutoffActivities.map(event => event.activity_id).filter(Boolean),
    explanation
  };
  return resource;
}

function aggregatePropagationStatus(resources) {
  if (!Array.isArray(resources) || resources.length === 0) return 'UNKNOWN';
  if (resources.some(resource => resource.state === 'FAILED')) return 'FAILED';
  if (resources.some(resource => resource.state === 'PENDING')) return 'PENDING';
  if (resources.some(resource => resource.state === 'RETENTION_PENDING')) return 'RETENTION_PENDING';
  if (resources.some(resource => resource.state === 'UNKNOWN_UNVERIFIED')) return 'UNKNOWN';
  return resources.every(resource => VERIFIED_STATES.has(resource.state)) ? 'COMPLETE' : 'UNKNOWN';
}

function analyzePropagation({
  request,
  profile,
  observations,
  activities,
  rules,
  systemFor,
  policyAction
}) {
  const cutoff = timestamp(request?.audit_at);
  if (cutoff === null) throw new TypeError('request.audit_at must be a valid ISO timestamp');

  const profileIdentifiers = identifiersFor(profile);
  const allObservationList = (observations || []).filter(observation => {
    const captured = timestamp(observation?.evidence?.captured_at);
    return captured !== null;
  });
  const observationList = allObservationList.filter(observation => timestamp(observation?.evidence?.captured_at) <= cutoff);
  const observedResourceIds = new Set(observationList.map(observation => text(observation.resource)).filter(Boolean));
  const allActivityList = (activities || []).filter(activity => {
    const eventTime = timestamp(activity.event_time);
    return eventTime !== null && (observedResourceIds.has(text(activity.resource_id)) || [...profileIdentifiers].some(identifier => norm(activity.details).includes(identifier)));
  });
  const activityList = allActivityList.filter(activity => timestamp(activity.event_time) <= cutoff);
  const resourceIds = new Set([
    ...observedResourceIds,
    ...activityList.map(activity => text(activity.resource_id)).filter(Boolean)
  ]);
  const resources = [...resourceIds].sort().map(resourceId => {
    const observation = observationList.find(item => text(item.resource) === resourceId) || null;
    const category = inferCategory(resourceId, observation?.object || {});
    const selectedRule = (rules || []).find(rule => norm(rule.data_category) === norm(category)) || null;
    return calculateResourcePropagation({
      request,
      profile,
      observation,
      outOfCutoffObservations: allObservationList.filter(item => text(item.resource) === resourceId && timestamp(item.evidence?.captured_at) > cutoff),
      activities: activityList.filter(activity => text(activity.resource_id) === resourceId),
      outOfCutoffActivities: allActivityList.filter(activity => text(activity.resource_id) === resourceId && timestamp(activity.event_time) > cutoff),
      rule: selectedRule,
      systemFor,
      policyAction
    });
  }).filter(resource => resource.resource_id !== 'unknown');

  const starts = resources.map(resource => resource.processing_start_at).filter(Boolean).sort();
  const completions = resources.map(resource => resource.verified_completion_at).filter(Boolean).sort();
  const requestedAt = iso(request.requested_at);
  const errors = [];
  if (!requestedAt) errors.push({ code: 'MISSING_REQUEST_TIMESTAMP', message: 'processing_delay_ms and propagation_ms require requested_at.', resource_id: null, evidence_id: null });
  for (const resource of resources) {
    if (resource.state === 'UNKNOWN_UNVERIFIED') {
      errors.push({ code: 'MISSING_TERMINAL_EVIDENCE', message: resource.explanation, resource_id: resource.resource_id, evidence_id: null });
    }
  }

  const caseStatus = aggregatePropagationStatus(resources);
  const allVerified = caseStatus === 'COMPLETE';
  const processingStartAt = starts[0] || null;
  const verifiedCompletionAt = allVerified ? completions.at(-1) || null : null;
  return {
    version: 1,
    case_id: request.case_id,
    case_status: caseStatus,
    requested_at: requestedAt,
    audit_at: iso(request.audit_at),
    processing_start_at: processingStartAt,
    processing_delay_ms: duration(requestedAt, processingStartAt),
    verified_completion_at: verifiedCompletionAt,
    verified_propagation_ms: duration(requestedAt, verifiedCompletionAt),
    resources,
    errors
  };
}

module.exports = {
  analyzePropagation,
  aggregatePropagationStatus,
  calculateResourcePropagation
};
