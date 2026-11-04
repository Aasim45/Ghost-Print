# GHOSTGUARD

A responsive, evidence-first deletion audit workspace for the HackerRank Orchestrate dataset. The local UI is served by a small Node.js service and reads participant-facing files from `dataset/`. No external systems are modified and proposed remediation is never shown as completed work.

## Run locally

Requires Node.js 20 or later. No package installation is required.

```bash
npm run dev
```

Open the URL printed by the server (normally <http://localhost:8000>). If that port is already occupied, the server automatically tries the next port and prints the new URL. You can also choose a port with `PORT=8080 npm run dev`. The UI includes Overview, Deletion Audits, individual audit details, Data Lineage, Risk Analysis, Certificates, Reports, and Settings. Search, filtering, sorting, pagination, evidence expanders, local integrity hashing, CSV downloads, and print-to-PDF are available.

## Run the FastAPI backend

Python 3.11 or later is required for the FastAPI service. From the repository root, create a virtual environment and install the backend dependencies:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r code\requirements.txt
python -m uvicorn backend.main:app --app-dir code --reload --host 127.0.0.1 --port 8000
```

Open <http://localhost:8000>. FastAPI serves the existing frontend and its same-origin `/api/*` routes. API documentation is available at <http://localhost:8000/docs>. The service stores parsed investigation results in `code/backend/ghostguard.sqlite3`; uploaded artifacts are isolated under `code/backend/uploads/` and are not automatically used to change a case result.

The Node server remains available as the no-install local preview. Do not run it and FastAPI on the same port at once.

## Optional AI audit explanations

The audit detail page has an **Explain with AI** button. To enable it, copy `code/.env.example` to `code/.env` and set `LLM_API_KEY`. The server defaults to the OpenAI-compatible Chat Completions endpoint and the `gpt-4.1-mini` model; `LLM_BASE_URL` or `LLM_CHAT_COMPLETIONS_URL` can select a compatible provider endpoint. `LLM_PROVIDER` is a display label. Restart the Node server after changing these settings. The server reads `.env` locally, and `.gitignore` excludes it.

The app makes no model request until a user clicks the button. That request sends a minimized case summary: status, audit cutoff, finding operations, system labels, resource categories, policy actions, and evidence references. It excludes subject identifiers, names, emails, phone numbers, raw evidence excerpts, and resource IDs. The AI provides an advisory explanation only; the evidence and policy engine remains responsible for status and remediation. Provider usage may incur charges under your account. Without a configured key, the UI explains how to configure AI and continues to work without it.

To set the required challenge output at repository root:

```bash
node code/server.js --export
```

`npm run dev` is configured by the repository-root `package.json` and works from `/workspaces/Ghost-Print`; no `npm install` step is needed.

## FastAPI integration

The browser service adapter is `frontend/api.js`; illustrative display-only examples live separately in `frontend/demo-data.js`. It expects the following routes, implemented by `backend/main.py`. Set `window.GHOSTGUARD_API_BASE` before `/api.js` loads to point the client to another origin.

- `GET /api/health`
- `GET /api/dashboard/summary`
- `GET /api/investigations?q=&status=&offset=&limit=`
- `GET /api/investigations/{case_id}`
- `GET /api/investigations/{case_id}/identity|findings|remediation|verification|graph|risks|certificate`
- `GET /api/investigations/{case_id}/evidence|timeline`
- `POST /api/investigations/{case_id}/ai-explanation` (optional, user-triggered AI explanation)
- `GET /api/datasets/official-challenge`
- `POST /api/datasets/upload` (validated, quarantined upload)
- `GET /api/risk-analysis`
- `GET /api/reports/export`

The UI consumes service responses through `GhostguardAPI`; mock records are not coupled to components. The backend returns evidence-linked observation nodes and only emits a lineage edge when a source record explicitly names both endpoints and a relationship. The case risk band is a disclosed prioritization heuristic, not a legal privacy guarantee.

Evidence matching, policy coverage, OCR support, and temporal reconstruction have known limitations; see `evaluation/evaluation_report.md`. Structural output validation does not establish prediction accuracy.

Run the backend unit checks after installing dependencies with `python -m pytest code/backend/test_engine.py`.

## Evidence and integrity boundaries

- Audit state is evaluated at the request's `audit_at` cutoff.
- Missing or unsupported evidence is not proof that data is gone.
- Findings cite evidence references from the generated audit steps.
- Remediation actions are recommendations only; the app cannot access customer systems.
- Hash-chain checks cover recorded audit metadata and evidence references. They do not prove deletion from the underlying systems.
- Example organization and activity labels are illustrative.

Run the challenge's structural validation with `node code/validate-output.js` after generating `output.csv`.
