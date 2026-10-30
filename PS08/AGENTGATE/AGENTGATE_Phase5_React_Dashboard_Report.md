# AGENTGATE Phase 5 — React Dashboard Report

## Delivered
- React 18 + Vite dashboard in `frontend/`.
- Responsive security console with API connection, event listing/pagination, exact-match audit filters, ALLOW/BLOCK snapshot, integrity verification, event details, and JSON/CSV exports.
- API key entry is held in React component state and is not persisted to local storage.
- Backend CORS allowlist supports local Vite development origins by default and can be configured through `AGENTGATE_CORS_ORIGINS`.
- External WORM archive remains excluded.

## Verification
- Full Python backend regression suite: **68 passed, 0 failures, 0 errors**.
- CORS preflight test passed for `http://127.0.0.1:5173`.
- Frontend production build: **not verified**. npm dependency installation timed out in this environment; do not interpret that as a successful build.

## Start the dashboard
1. Start your existing configured AGENTGATE backend with a valid API key mapping, active registered session, and an `audit_readers` allowlist containing the mapped user.
2. From `frontend/`, run `npm install`.
3. Copy `.env.example` to `.env` if you want to set `VITE_AGENTGATE_API_URL`.
4. Run `npm run dev` and open the URL printed by Vite.
5. Enter the Gateway API key in the dashboard.

## Important
The dashboard cannot create an authorized session or grant audit-reader permission. Those must be configured by trusted backend startup code. For production, set `AGENTGATE_CORS_ORIGINS` to only the deployed dashboard origins. External AWS WORM archive is not included in this phase.
