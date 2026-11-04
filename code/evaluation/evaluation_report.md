# GHOSTGUARD evaluation report

## Evaluation scope

The implementation includes deterministic request classification, current and historical identifier lookup, a cutoff-aware evidence reader, resource observations, policy-action lookup, and required output serialization. Only public participant-facing files are read. The organizer's evaluation entry point is not an answer source and was not used.

## Measured public-sample metrics

The deterministic implementation was run against all 32 public rows in `sample_deletion_requests.csv`, compared with `sample_output.csv`, using `node code/server.js --evaluate-sample`.

| Metric | Result |
|---|---:|
| Case status accuracy | 21 / 32 (65.63%) |
| Exact step sequence accuracy | 1 / 32 (3.13%) |
| Exact step accuracy | 3 / 193 expected steps (1.55%) |
| Step-field accuracy | 286 / 567 compared fields (50.44%) |

These results are weak, especially for step sequence. They show that this prototype is not ready to claim challenge-quality predictions. No hidden-answer or full-dataset accuracy is claimed. Use `node code/server.js --export` to write an experimental output, then `node code/validate-output.js` for structural validation only.

## Team-designed test cases

1. A clear English erase request is classified as deletion.
2. A Spanish `eliminar` request is classified as deletion.
3. An export request, an account update explicitly saying not to delete, and a marketing unsubscribe are not deletion requests.
4. CSV request text containing commas and escaped double quotes is parsed without column shifting.

These checks are implemented in `test/server.test.js` and run with `node --test code/test/*.test.js`.

## Known failures and next improvements

- PDF and image artifacts are inventoried but not OCR/text-extracted. SQL files are treated as text and are not executed; robust table-aware snapshot reconstruction is still needed.
- Evidence matching currently supports exact normalized values in structured records and matching text lines. It does not resolve every indirect hash, shared support context, legal hold, retention window, or SQL row relationship.
- The resource-level evidence parser does not yet establish every COPY/SYNC/IMPORT/RESTORE edge. The graph intentionally does not draw unsupported edges.
- A missing proof yields `INCOMPLETE`, but a complete case requires a supported verification observation. Case accuracy has not been measured, and some borderline request language requires a stronger multilingual classifier.
- The dataset manager exposes the supplied manifest and missing-file errors. Arbitrary dataset upload is not enabled. No external remediation integration exists; planner items are proposals only.
- Persistence is in-memory for this local build. Investigation results can be recomputed after restart; SQLite persistence remains future work.

Improvements should prioritize table-aware SQL and structured log readers, PDF/image OCR, policy-complete treatment rules, explicit temporal resource state reconstruction, graph evidence, persistent storage, and systematic comparison against all public sample answers.
