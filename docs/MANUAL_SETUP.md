# PatchPilot — Manual Setup Guide

This document describes every step required to bring PatchPilot back to a fully operational state after a PC reset or fresh installation.

---

## Prerequisites

| Tool | Minimum Version | Install |
|---|---|---|
| Python | 3.11+ | `sudo apt install python3 python3-venv` |
| Node.js | 18+ | `https://nodejs.org` or `nvm install 18` |
| npm | 8+ | Bundled with Node.js |
| Docker | 24+ | `https://docs.docker.com/engine/install/` |
| Git | any | `sudo apt install git` |

> **On this machine:** Python 3.14.4 ✅, Node.js 22.22.1 ✅, npm 9.2.0 ✅, Docker ❌ (not installed — install first).

---

## Step 1 — Install Docker

Docker is required to run FalkorDB unless you install FalkorDB natively.

```bash
# Ubuntu / Debian
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
# Log out and back in for group membership to take effect
docker --version   # should print Docker version
```

Alternative (Snap):
```bash
sudo snap install docker
```

---

## Step 2 — Start FalkorDB

**Option A — Docker (recommended):**
```bash
cd patchpilot
docker compose up -d falkordb
```

**Option B — Docker one-liner (no compose):**
```bash
docker run -d --name patchpilot-falkordb -p 6379:6379 falkordb/falkordb:latest
```

**Verify FalkorDB is running:**
```bash
python3 -c "import socket; s=socket.socket(); r=s.connect_ex(('localhost',6379)); print('FalkorDB: OK' if r==0 else 'FalkorDB: NOT REACHABLE')"
```

---

## Step 3 — Set Up the Python Backend

```bash
cd patchpilot/backend

# Create a fresh virtual environment
python3 -m venv venv

# Install all dependencies
./venv/bin/pip install -r requirements.txt

# Verify key packages
./venv/bin/python -c "import falkordb, fastapi, uvicorn; print('All packages OK')"
```

### 3a — Create the `.env` file

```bash
cp .env.example .env
```

Edit `.env` if needed (e.g. to add an LLM API key):

```
FALKORDB_HOST=localhost
FALKORDB_PORT=6379
FALKORDB_PASSWORD=
FALKORDB_GRAPH=patchpilot
LLM_PROVIDER=deterministic      # Change to "openai" if you have a key
OPENAI_API_KEY=                  # Paste your key here if using OpenAI
```

> **The application works fully in `deterministic` mode** — graph traversal, prioritization, evidence paths, and remediation persistence all function without any LLM API key. Only the `llm_summary` field in the investigation response is omitted.

### 3b — Start the Backend

```bash
cd patchpilot/backend
./venv/bin/uvicorn app.main:app --reload --port 8000
```

On first start, the backend automatically seeds the graph with synthetic data if the graph is empty.

Swagger UI: **`http://localhost:8000/docs`**
Health check: **`http://localhost:8000/api/health`**

---

## Step 4 — Set Up the Frontend

```bash
cd patchpilot/frontend

# Install dependencies (already present in node_modules if restored from ZIP)
npm install

# (Optional) Create frontend env file — default works without it
cp .env.example .env   # VITE_API_BASE_URL=http://localhost:8000

# Start the dev server
npm run dev
```

Visit **`http://localhost:5173`** to access PatchPilot.

---

## Step 5 — Seed Graph Data (Optional — auto-seeded on backend start)

The backend auto-seeds on startup if the graph is empty. To manually seed or re-seed:

```bash
# Via the API (while backend is running):
curl -X POST http://localhost:8000/api/seed

# Re-seed from scratch (clears existing data):
curl -X POST "http://localhost:8000/api/seed?clear_first=true"

# Via the standalone script:
cd patchpilot/backend
./venv/bin/python ../scripts/seed_graph.py
# Or with --clear:
./venv/bin/python ../scripts/seed_graph.py --clear
```

---

## Step 6 — Run Tests

```bash
cd patchpilot/backend

# Unit tests only (no FalkorDB required):
./venv/bin/pytest tests/ -v -m "not integration"

# All tests (requires FalkorDB running):
./venv/bin/pytest tests/ -v
```

Expected results:
- **Unit tests (13):** All pass regardless of DB state.
- **Integration tests (32):** Pass only when FalkorDB is running and seeded.

---

## Environment Variables Reference

### Backend (`backend/.env`)

| Variable | Default | Required | Description |
|---|---|---|---|
| `FALKORDB_HOST` | `localhost` | Yes | FalkorDB host |
| `FALKORDB_PORT` | `6379` | Yes | FalkorDB port (Redis-compatible) |
| `FALKORDB_PASSWORD` | `` | No | Leave blank for unauthenticated |
| `FALKORDB_GRAPH` | `patchpilot` | No | Graph name |
| `BACKEND_HOST` | `0.0.0.0` | No | API bind address |
| `BACKEND_PORT` | `8000` | No | API port |
| `CORS_ORIGINS` | `http://localhost:5173,...` | No | Allowed frontend origins |
| `LLM_PROVIDER` | `deterministic` | No | `deterministic`, `openai`, or `anthropic` |
| `OPENAI_API_KEY` | `` | No (optional) | Required only when `LLM_PROVIDER=openai` — obtain at `https://platform.openai.com/api-keys` |
| `ANTHROPIC_API_KEY` | `` | No (optional) | Required only when `LLM_PROVIDER=anthropic` — obtain at `https://console.anthropic.com/` |
| `LOG_LEVEL` | `INFO` | No | Logging verbosity |

### Frontend (`frontend/.env`)

| Variable | Default | Description |
|---|---|---|
| `VITE_API_BASE_URL` | `http://localhost:8000` | Backend API base URL |

---

## Verification Checklist

After completing setup, verify each item:

- [ ] `docker ps` shows `patchpilot-falkordb` running
- [ ] `curl http://localhost:6379` receives a response (port open)
- [ ] `curl http://localhost:8000/api/health` returns `{"status":"ok","falkordb":"ok",...}`
- [ ] `curl http://localhost:8000/api/vulnerabilities` returns 4 vulnerabilities
- [ ] `curl -X POST http://localhost:8000/api/investigate -H "Content-Type: application/json" -d '{"vuln_id":"VULN-2024-001"}'` returns a full investigation result
- [ ] `http://localhost:5173` loads the PatchPilot web UI
- [ ] FalkorDB status dot in sidebar shows green
- [ ] Investigation produces a priority score and evidence paths
- [ ] Approving a remediation stores it and shows in Remediations page

---

## Docker Compose (Full Stack)

To run FalkorDB + backend together:

```bash
cd patchpilot
docker compose up -d
```

Add your LLM key (optional):
```bash
OPENAI_API_KEY=sk-your-key docker compose up -d
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `FalkorDB: NOT REACHABLE` | FalkorDB container not running | `docker compose up -d falkordb` |
| Backend starts but returns 500 | Graph not seeded | `POST /api/seed` or restart backend (auto-seeds) |
| `venv/bin/pip: bad interpreter` | Venv created on different machine | `python3 -m venv venv --clear && ./venv/bin/pip install -r requirements.txt` |
| Frontend shows "backend not running" | Backend not started | Start backend first: `./venv/bin/uvicorn app.main:app --port 8000` |
| `docker: command not found` | Docker not installed | See Step 1 above |
