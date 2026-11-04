# GHOSTGUARD evaluation report

## Evaluation scope

The repository now includes a FastAPI backend with SQLite persistence, deterministic request classification, time-bounded identity lookup, JSON/text/PDF/image readers, an isolated in-memory reader for official SQL snapshots, policy lookup, and required output serialization. Only participant-facing dataset files are used. Organizer evaluation sources were not inspected or used. The FastAPI backend has not been executed in this environment because Python is not installed.

## Measured public-sample metrics

The previous Node backend was run against all 32 public rows in `sample_deletion_requests.csv`, compared with `sample_output.csv`, using `node code/server.js --evaluate-sample`. These results are a baseline for the earlier Node implementation; they are not measurements of the new FastAPI backend.

| Metric | Result |
|---|---:|
| Case status accuracy | 21 / 32 (65.63%) |
| Exact step sequence accuracy | 1 / 32 (3.13%) |
| Exact step accuracy | 3 / 193 expected steps (1.55%) |
| Step-field accuracy | 286 / 567 compared fields (50.44%) |

These results are weak, especially for step sequence. No hidden-answer accuracy is claimed. The FastAPI backend requires a fresh public-sample evaluation and output validation before it should be used to submit predictions.

## Team-designed test cases

1. A clear English erase request is classified as deletion.
2. A Spanish `eliminar` request is classified as deletion.
3. An export request, an account update explicitly saying not to delete, and a marketing unsubscribe are not deletion requests.
4. CSV request text containing commas and escaped double quotes is parsed without column shifting.

These checks are implemented in `test/server.test.js` and run with `node --test code/test/*.test.js`.

## Known failures and next improvements

- Image OCR depends on a local Tesseract binary and can be unavailable. PDF text extraction and SQL snapshot parsing are implemented but have not been run here.
- Evidence matching currently supports exact normalized values in structured records and matching text lines. It does not resolve every indirect hash, shared support context, legal hold, retention window, or SQL row relationship.
- The resource-level evidence parser does not yet establish every COPY/SYNC/IMPORT/RESTORE edge. The graph intentionally does not draw unsupported edges.
- A missing proof yields `INCOMPLETE`, but complete status still needs careful verification of every applicable policy requirement. FastAPI case accuracy is unmeasured, and borderline multilingual intent needs a stronger classifier.
- Uploads are validated and quarantined but do not affect investigations. No external remediation integration exists; planner items are proposals only.
- FastAPI persists case results in SQLite. Database migration and concurrent batch processing have not been load-tested.

Improvements should prioritize policy-complete treatment rules, explicit temporal resource reconstruction, supported process edges, OCR coverage, and systematic comparison of FastAPI results against all public sample answers.
