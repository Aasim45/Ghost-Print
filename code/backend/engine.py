        if resolved != "RESOLVED":
            cause = "IDENTITY_AMBIGUOUS" if resolved == "AMBIGUOUS" else "IDENTITY_UNRESOLVED"
            explanation = explain_audit_status("INCOMPLETE", cause)
            return self._make_result(case_id, "INCOMPLETE", request, identity, [], [], explanation)

        cutoff = parse_time(request.get("audit_at"))
        findings = []
        safe_checks = []
        matched_evidence_ids = []
        resource_missing_evidence_ids = []
        unsupported_policy = {}

        for evidence in self.evidence:
            captured = parse_time(evidence.get("captured_at"))
            if evidence.get("error") or (cutoff and captured and captured > cutoff):
                continue

            records = list(evidence.get("records", []))

            if not records and evidence.get("content"):
                for line in evidence["content"].splitlines():
                    if not any(identifier and identifier in normalized(line) for identifier in identifiers):
                        continue

                    match = re.search(
                        r"\b(?:account|search|support|analytics|export|backup|tombstone|data_flow|audit_record)_[0-9][\w-]*\b",
                        line,
                        re.I
                    )

                    if match:
                        inline = {"resource_id": match.group(), "line": line}
                        email_match = re.search(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", line)
                        if email_match:
                            inline["email"] = email_match.group()

                        state_match = re.search(
                            r"\b(NOT_FOUND|ABSENT|DELETED|REDACTED|ANONYMIZED|ANONYMISED|ACTIVE|ENABLED|RUNNING|FOUND|PRESENT|IDENTIFIABLE|BLOCKED|DISABLED)\b",
                            line,
                            re.I
                        )
                        if state_match:
                            inline["state"] = state_match.group(1).upper()

                        records.append(inline)

            for record in records:
                if not isinstance(record, dict) or not self._matches(record, identifiers):
                    continue

                event_time = parse_time(field_value(
                    record,
                    {"event_time", "timestamp", "updated_at", "captured_at", "observed_at", "created_at"}
                ))

                if cutoff and event_time and event_time > cutoff:
                    continue

                if evidence.get("file_id"):
                    matched_evidence_ids.append(evidence["file_id"])

                resource_value = record.get(
                    "resource_id",
                    record.get("file_id", record.get("activity_id", ""))
                )
                resource = str(resource_value).strip() if resource_value is not None else ""

                if not resource:
                    if evidence.get("file_id"):
                        resource_missing_evidence_ids.append(evidence["file_id"])
                    continue

                category = self._category(record, resource)
                rule = self.rules.get(category, {})
                treatment = str(rule.get("required_action", "")).upper()

                if treatment not in {"DELETE", "REDACT", "ANONYMIZE", "RETAIN"}:
                    unsupported_policy.setdefault(category, set()).add(evidence.get("file_id", ""))

                system = str(record.get(
                    "system_id",
                    record.get("origin_system", record.get("source_system", ""))
                ))

                system = system or {
                    "USER_PROFILE": "account_service",
                    "SEARCH_INDEX_ENTRY": "search_service",
                    "ANALYTICS_PROFILE": "analytics_platform",
                    "PRODUCT_TELEMETRY": "analytics_platform",
                    "SUPPORT_MESSAGE": "support_platform",
                    "SUPPORT_ATTACHMENT": "support_platform",
                    "USER_EXPORT": "export_service",
                    "BACKUP_ARCHIVE": "backup_service",
                    "ACCOUNT_TOMBSTONE": "identity_service",
                    "SECURITY_AUDIT_LOG": "security_service"
                }.get(category, "unknown")

                state = self._state(record)
                active = state in {"ACTIVE", "ENABLED", "RUNNING", "RESTORABLE", "AVAILABLE"}

                pii = any(
                    k in {"email", "phone", "full_name", "name", "email_hash"} and v not in (None, "")
                    for k, v in values_in(record)
                )

                operation = None
                step_state = "PRESENT"

                if "data_flow" in resource.casefold() and active:
                    operation, step_state = "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"
                elif category == "BACKUP_ARCHIVE" and active:
                    operation, step_state = "REPORT_RESTORE_RISK", "ACTIVE"
                elif treatment == "RETAIN":
                    safe_checks.append((
                        system, resource, "VERIFY_RECORD_PRESENT", "PRESENT",
                        evidence["file_id"], category
                    ))
                    continue
                elif treatment == "DELETE" and state not in {"ABSENT", "NOT_FOUND", "DELETED"}:
                    operation = "REPORT_REMAINING_RECORD"
                elif treatment in {"REDACT", "ANONYMIZE"} and pii:
                    operation = "REPORT_EXPOSED_PII"

                if operation:
                    excerpt = " ".join(
                        str(v) for k, v in record.items()
                        if k.casefold() in {"state", "status", "category", "event_type", "operation_result"}
                    )[:240]

                    reason, recommended = explain_finding(
                        operation, system, resource, category, treatment
                    )

                    findings.append({
                        "phase": "FINDING",
                        "system_id": system,
                        "resource_id": resource,
                        "operation": operation,
                        "state": step_state,
                        "evidence_id": evidence["file_id"],
                        "data_category": category,
                        "evidence_excerpt": excerpt,
                        "policy_action": treatment,
                        "reason": reason,
                        "recommended_action": recommended,
                        "_record": record
                    })

                elif treatment in {"DELETE", "REDACT", "ANONYMIZE"}:
                    op = {
                        "DELETE": "VERIFY_RECORD_ABSENT",
                        "REDACT": "VERIFY_RECORD_REDACTED",
                        "ANONYMIZE": "VERIFY_RECORD_ANONYMIZED"
                    }[treatment]

                    state_out = {
                        "DELETE": "ABSENT",
                        "REDACT": "REDACTED",
                        "ANONYMIZE": "ANONYMIZED"
                    }[treatment]

                    safe_checks.append((
                        system, resource, op, state_out, evidence["file_id"], category
                    ))

        findings = self._dedupe(findings)