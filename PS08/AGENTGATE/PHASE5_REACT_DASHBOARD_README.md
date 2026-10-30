# AGENTGATE Phase 5 — React Dashboard

This folder adds a React/Vite security dashboard to the unified Phase 1–4 backend. The external WORM archive remains excluded, as requested.

## Dashboard features

- Gateway connection status and API key entry (key stays in React component state; it is not saved to local storage).
- Audit event table with pagination and exact-match filters.
- ALLOW/BLOCK summary for the currently loaded page.
- HMAC audit-chain verification via `GET /v1/audit/verify`.
- JSON and CSV export using the existing API.
- Event detail drawer/modal.
- Responsive desktop and mobile layout.
- Clear handling for `401`, `403`, API unreachable, and CORS errors.

## Run locally (Windows)

Requirements: Python 3.10+ and Node.js 18+ with npm. From this project folder, run:

```powershell
.\start-agentgate.ps1
```

The script creates a local `.env` with random development credentials on first run, installs missing dependencies, starts the API and dashboard, and opens the dashboard. Paste the printed **Dashboard API key** into the dashboard's Gateway API key field. The key is stored only in `.env` and is ignored by Git. To restart later, use the same command; the key will remain the same.

The backend entry point is `agentgate_phase1/app.py` (`uvicorn app:app --host 127.0.0.1 --port 8000`). It validates the configured secrets and API-key map, registers configured sessions in the local SQLite store, and permits audit access only for identities explicitly listed in `AGENTGATE_AUDIT_READERS`. For manual startup, set `AGENTGATE_AUTH_KEY`, `AGENTGATE_AUDIT_KEY`, `AGENTGATE_API_KEYS`, and `AGENTGATE_AUDIT_READERS` in the server environment before running Uvicorn. Never commit production credentials.

On Windows, the backend and audit dashboard run normally, but file read/write endpoints return `503`: the file-security layer intentionally fails closed when the platform does not provide the required directory-handle protections. Use a supported POSIX platform for those operations.

Production: build static assets with `npm run build`. Configure `AGENTGATE_CORS_ORIGINS` to include only the deployed dashboard origin(s).

## API endpoints used

- `GET /health`
- `GET /v1/audit?limit=50&offset=0` with exact-match filters
- `GET /v1/audit/verify`
- `GET /v1/audit/export?format=json&limit=5000`
- `GET /v1/audit/export?format=csv&limit=5000`
- `GET /v1/audit/{event_id}`

## Phase 5 scope

This is the dashboard layer. It does not change policy decisions or bypass gateway authorization. It does not include AWS/WORM archive functionality.
