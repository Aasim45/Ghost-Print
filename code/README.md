# GHOSTGUARD

A responsive, evidence-first deletion audit workspace for the HackerRank Orchestrate dataset. The local UI is served by a small Node.js service and reads participant-facing files from `dataset/`. No external systems are modified and proposed remediation is never shown as completed work.

## Run locally

Requires Node.js 20 or later. No package installation is required.

```bash
npm run dev
```

Open the URL printed by the server (normally <http://localhost:8000>). If that port is already occupied, the server automatically tries the next port and prints the new URL. You can also choose a port with `PORT=8080 npm run dev`. The UI includes Overview, Deletion Audits, individual audit details, Data Lineage, Risk Analysis, Certificates, Reports, and Settings. Search, filtering, sorting, pagination, evidence expanders, local integrity hashing, CSV downloads, and print-to-PDF are available.

To set the required challenge output at repository root:

```bash
node code/server.js --export
```

`npm run dev` is configured by the repository-root `package.json` and works from `/workspaces/Ghost-Print`; no `npm install` step is needed.

## FastAPI integration

The browser service adapter is `frontend/api.js`; illustrative display-only examples live separately in `frontend/demo-data.js`. It expects the following routes, matching the local Node service. Set `window.GHOSTGUARD_API_BASE` before `/api.js` loads to point the client to another origin.

- `GET /api/health`
- `GET /api/dashboard/summary`
- `GET /api/investigations?q=&status=&offset=&limit=`
- `GET /api/investigations/{case_id}`
- `GET /api/investigations/{case_id}/identity|findings|remediation|verification|graph|risks|certificate`
- `GET /api/datasets/official-challenge`
- `GET /api/risk-analysis`
- `GET /api/reports/export`

The UI consumes service responses through `GhostguardAPI`; mock records are not coupled to components. The current backend returns evidence-linked observation nodes but no lineage edges when the supplied evidence does not establish a relationship. Risk score is a disclosed prioritization heuristic, not a legal privacy guarantee.

## Evidence and integrity boundaries

- Audit state is evaluated at the request's `audit_at` cutoff.
- Missing or unsupported evidence is not proof that data is gone.
- Findings cite evidence references from the generated audit steps.
- Remediation actions are recommendations only; the app cannot access customer systems.
- Hash-chain checks cover recorded audit metadata and evidence references. They do not prove deletion from the underlying systems.
- Example organization and activity labels are illustrative.

Run the challenge's structural validation with `node code/validate-output.js` after generating `output.csv`.
