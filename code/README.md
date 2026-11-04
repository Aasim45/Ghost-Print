# GHOSTPRINTS

Local, evidence-first deletion-audit workspace for HackerRank Orchestrate October 2026.

## Requirements

- Node.js 20 or later
- The challenge's `dataset/` directory beside `code/`

This workspace has no Python installation. The delivered prototype therefore uses Node.js built-ins and does not require `npm install`. It reads the challenge dataset in place and never modifies the source evidence.

## Run the application

From the repository root:

```powershell
node code/server.js
```

Open `http://localhost:8000`. To write the challenge output at repository root:

```powershell
node code/server.js --export
```

To run the automated checks:

```powershell
node --test code/test/*.test.js
```

## API

- `GET /api/health`
- `GET /api/dashboard/summary`
- `GET /api/datasets` and `GET /api/datasets/official-challenge`
- `GET /api/investigations?q=&status=&offset=&limit=`
- `POST /api/investigations/run`
- `GET /api/investigations/{case_id}`
- `GET /api/investigations/{case_id}/evidence|timeline|graph|risks|remediation`
- `GET /api/reports/export`

The API serves the bundled frontend. API errors use JSON and appropriate HTTP status codes.

## Important implementation limits

This is a runnable prototype, not a complete production or challenge-accuracy claim. It reads structured JSON and exact identifier occurrences in text evidence, and respects manifest capture time as a conservative cutoff. PDF/image OCR, SQL table reconstruction, complete temporal event interpretation, all policy conditions, graph edge verification, upload, SQLite persistence, and complete evaluation are not implemented yet. Missing verification is never represented as proof of absence. Some output cases can therefore be incomplete without a concrete remediation step, and generated predictions must be reviewed before submission.

No external system is modified. No LLM credentials are required. Proposed operations are not presented as executed actions. Findings cite manifest `file_id` values; future remediation and follow-up checks use empty evidence IDs.
