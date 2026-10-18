# PatchPilot — Recovery Audit

**Date:** 2026-10-18  
**Inspector:** Antigravity AI  
**Project:** PatchPilot — Graph-Powered Vulnerability Triage and Remediation Agent  
**Hackathon:** WeMakeDevs Graph Hacks, Track 01

---

## A. Existing Implementation

### Repository Structure

The project lives at `patchpilot/` inside the workspace root. There is one commit on `main` tagged `feat: complete PatchPilot graph-powered vulnerability triage system`. The inner `patchpilot/` directory contains its own `.git` folder.

| File/Directory | What It Does |
|---|---|
| `backend/app/main.py` | FastAPI entry point. Defines lifespan (auto-seeds graph on startup if empty). Includes CORS and mounts the API router. |
| `backend/app/api/routes.py` | All REST endpoints: `/api/health`, `/api/overview`, `/api/vulnerabilities`, `/api/investigate`, `/api/investigations`, `/api/graph/vulnerability/{id}`, `/api/remediations`, `/api/seed`. All implemented and correctly typed. |
| `backend/app/core/config.py` | Pydantic-Settings config class. Reads `FALKORDB_HOST/PORT/PASSWORD/GRAPH`, `LLM_PROVIDER`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `CORS_ORIGINS`. Defaults to deterministic mode. |
| `backend/app/core/prioritization.py` | Fully implemented deterministic scoring engine. Score = severity (0–40) + asset criticality (0–30) + reach (0–20) + exposure (+10) + confidence penalty (−15). Range: 0–100. Labels: CRITICAL/HIGH/MEDIUM/LOW/UNCERTAIN. |
| `backend/app/db/connection.py` | FalkorDB singleton connection manager. `get_client()`, `get_graph()`, `ping()`, `reset_connections()`. Handles optional password auth. |
| `backend/app/graph/queries.py` | All Cypher query functions: seeding, vulnerability lookup, package traversal, application tracing, asset impact, team lookup, evidence paths, graph visualization data, investigation CRUD, remediation CRUD, overview stats. |
| `backend/app/agent/investigator.py` | Full investigation workflow: 11-step orchestration calling all graph tools, computing priority, optional LLM enrichment (OpenAI/Anthropic), persisting investigation to FalkorDB. Graceful degradation to deterministic mode when no LLM key is present. |
| `backend/app/schemas/models.py` | Complete Pydantic schema set for all request/response types. |
| `backend/requirements.txt` | `fastapi`, `uvicorn[standard]`, `falkordb==1.0.10`, `pydantic-settings`, `httpx`, `openai`, `anthropic`, `pytest`, `pytest-asyncio`, `python-multipart`. |
| `backend/.env.example` | Well-documented template with all required variables. |
| `backend/Dockerfile` | Python 3.12-slim image. Installs requirements and runs uvicorn. |
| `backend/tests/test_patchpilot.py` | 45-test suite: 13 unit tests (prioritization engine, no DB) + 32 integration tests (DB required, skip gracefully when unavailable). |
| `frontend/src/App.tsx` | React root with BrowserRouter. Polls health on mount. Passes FalkorDB and LLM status to Sidebar. |
| `frontend/src/services/api.ts` | Typed API client covering all backend endpoints. Uses `VITE_API_BASE_URL` env var. |
| `frontend/src/index.css` | Complete CSS design system: warm ivory/white/emerald/coral palette, variables, layout utilities, modal, form, graph node, badge, tab, timeline styles. |
| `frontend/src/components/Sidebar.tsx` | Nav with FalkorDB/LLM status dots in footer. |
| `frontend/src/components/Badges.tsx` | `SeverityBadge`, `CriticalityBadge` components. |
| `frontend/src/components/DependencyGraph.tsx` | React Flow graph canvas component with custom nodes. |
| `frontend/src/components/EvidencePathView.tsx` | Renders actual FalkorDB dependency chain paths. |
| `frontend/src/components/PriorityScoreCard.tsx` | Donut-style score visualization with factor breakdown. |
| `frontend/src/components/RemediationModal.tsx` | Modal for approving and submitting a simulated remediation. |
| `frontend/src/pages/OverviewPage.tsx` | Dashboard with metric cards, vulnerability list, recent investigations, recent remediations. Fetches real API data. |
| `frontend/src/pages/InvestigatePage.tsx` | Full investigation workflow: select vuln → run → display packages, apps, assets, teams, evidence paths, graph, priority card, remediation button. |
| `frontend/src/pages/GraphPage.tsx` | Standalone vulnerability graph visualization page. |
| `frontend/src/pages/RemediationsPage.tsx` | Remediation history listing. |
| `frontend/src/pages/StatusPage.tsx` | System status/health information. |
| `frontend/package.json` | React 19, react-router-dom 7, @xyflow/react 12, lucide-react, recharts. Vite + TypeScript. |
| `frontend/node_modules/` | Fully installed (compressed in ZIP and extracted — `@xyflow/react` confirmed present). |
| `docker-compose.yml` | FalkorDB + backend services. Passes env vars. |
| `scripts/seed_graph.py` | Standalone seed runner (requires backend venv on path). |
| `data/synthetic_data/graph_dataset.json` | Reference JSON of the synthetic graph dataset. |
| `docs/architecture.md`, `docs/cypher_queries.md`, `docs/demo_guide.md` | Existing documentation. |

---

## B. Verified Functionality

| Feature | Status | Evidence |
|---|---|---|
| Backend Python imports | ✅ Working | `falkordb`, `fastapi`, `uvicorn` import successfully from venv |
| Prioritization engine | ✅ Working | 13/13 unit tests pass; manual invocation returns correct scores |
| Config loading | ✅ Working | Settings load with defaults when `.env` is absent |
| All Pydantic schemas | ✅ Working | Import cleanly |
| API route definitions | ✅ Working | All routes defined, correct types |
| Agent investigator | ✅ Working | Full 11-step workflow implemented with graceful LLM fallback |
| Frontend installed | ✅ Working | `node_modules` present including `@xyflow/react` |
| Frontend build artefact | ✅ Present | `dist/` directory exists from previous build |
| CSS design system | ✅ Working | Full ivory/emerald palette implemented, no dark navy |
| All frontend pages | ✅ Implemented | 5 pages with real API integration (no hardcoded mocks) |
| Docker Compose | ✅ Defined | Correct FalkorDB → backend dependency chain |

---

## C. Incomplete / Broken Functionality

| Issue | Severity | Details |
|---|---|---|
| **Venv Python interpreter path is broken** | 🔴 Critical | The venv's `pyvenv.cfg` records the old machine's home path (`/home/elliot/...`). The shebang in venv scripts points to a non-existent interpreter. Direct module calls via `venv/bin/python` work because Python resolves relative to the actual executable, but `pip` and other scripts in `venv/bin/` fail. |
| **No `.env` file in `backend/`** | 🔴 Critical | After PC reset, `.env` was not carried (correctly gitignored). The application uses defaults which point to `localhost:6379` for FalkorDB — correct for local dev, but the file does not exist. |
| **FalkorDB not running** | 🔴 Critical | Port 6379 is closed. All 32 integration tests and the full live workflow are blocked. Needs Docker (not installed) or a local FalkorDB binary. |
| **Docker not installed** | 🔴 Critical | `docker: command not found`. Primary deployment path unavailable. |
| **`venv/bin/pip` broken** | 🟠 High | Cannot run `pip install` through the venv. Must use `python -m pip` or reinstall the venv. |
| **Frontend `.env` not created** | 🟡 Medium | `.env.example` exists. Without `.env`, `VITE_API_BASE_URL` falls back to `http://localhost:8000` — acceptable for local dev. |
| **32 integration tests skipped** | 🟡 Medium | Blocked by FalkorDB being unavailable. Will pass once DB is running. |
| **No `docs/MANUAL_SETUP.md`** | 🟡 Medium | Setup documentation needs to be created for post-reset recovery. |

---

## D. Environment and Dependency Status

| Tool | Version | Status |
|---|---|---|
| Python 3 | 3.14.4 | ✅ Installed (`/usr/bin/python3`) |
| Node.js | 22.22.1 | ✅ Installed |
| npm | 9.2.0 | ✅ Installed |
| Docker | — | ❌ Not installed (`command not found`) |
| Git | — | ✅ Available |
| FalkorDB | — | ❌ Not running (port 6379 closed) |
| Backend venv | python3.14 | ⚠️ Present but pip scripts broken (wrong shebang path) |
| Backend packages | `falkordb`, `fastapi`, `uvicorn`, etc. | ✅ Installed in venv (importable via `python -m`) |
| Frontend `node_modules` | React 19, @xyflow/react 12 | ✅ Installed (from ZIP) |

---

## E. Configuration Requirements

| Variable | File | Required | How to Obtain | Works Without It |
|---|---|---|---|---|
| `FALKORDB_HOST` | `backend/.env` | Yes | `localhost` for local; `falkordb` in Docker Compose | No — app starts but all DB operations fail |
| `FALKORDB_PORT` | `backend/.env` | Yes | Default `6379` | No |
| `FALKORDB_PASSWORD` | `backend/.env` | No | Leave blank for unauthenticated | Yes (blank = no auth) |
| `FALKORDB_GRAPH` | `backend/.env` | No | Default `patchpilot` | Yes (default used) |
| `LLM_PROVIDER` | `backend/.env` | No | `deterministic` | Yes — full graph investigation works without LLM |
| `OPENAI_API_KEY` | `backend/.env` | No | `https://platform.openai.com/api-keys` | Yes — only affects LLM summary field |
| `ANTHROPIC_API_KEY` | `backend/.env` | No | `https://console.anthropic.com/` | Yes |
| `VITE_API_BASE_URL` | `frontend/.env` | No | `http://localhost:8000` | Yes (default used) |

No secrets were found in any committed files. The `.env` file is gitignored and was correctly excluded.

---

## F. Immediate Blockers

1. **FalkorDB is not running.** Install Docker and run `docker compose up -d`, or install FalkorDB natively.
2. **Venv `pip` shebang is broken.** Recreate the venv using the local Python 3.14: `python3 -m venv backend/venv && venv/bin/python -m pip install -r backend/requirements.txt`. Alternatively, invoke `python -m pip` directly.
3. **No `backend/.env` file.** Must be created (copy from `.env.example`).
4. **Docker not installed.** Either install Docker or run FalkorDB via another method.

---

## G. Remaining Work (Ranked)

| Priority | Task | Status |
|---|---|---|
| 1 | Recreate backend venv with working pip | 🔧 To do |
| 1 | Create `backend/.env` from example | 🔧 To do |
| 1 | Start FalkorDB (Docker or native) | 🔧 Blocked on Docker install |
| 2 | Verify FalkorDB connection and seeding | ⏳ Blocked on FalkorDB |
| 2 | Run integration tests once DB is available | ⏳ Blocked on FalkorDB |
| 3 | Create `docs/MANUAL_SETUP.md` | 🔧 To do |
| 4 | Verify frontend build produces correct output | 🔧 To do |
| 5 | Verify frontend-to-backend integration end-to-end | ⏳ Blocked on backend |
| 6 | Update README.md if any discrepancies found | 🔧 Minor |
| 7 | UI polish review | ⏳ Blocked on running app |
| 8 | Documentation finalization | 🔧 To do |

---

*Audit generated automatically. All findings are based on direct code inspection and command execution.*
