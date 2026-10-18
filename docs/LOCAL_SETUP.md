# 🛠️ PatchPilot Local Setup & Execution Guide

This guide details how to set up, configure, seed, test, and run **PatchPilot** locally from scratch on Linux (Ubuntu/Debian), macOS, or Windows (WSL2).

---

## 1. System Prerequisites

Ensure the following tools are installed on your host machine:

| Requirement | Minimum Version | Recommended | Verification Command |
| :--- | :--- | :--- | :--- |
| **Python** | 3.11+ | 3.11, 3.12, 3.13, 3.14 | `python3 --version` |
| **Node.js** | 18+ | 20 LTS or 22 LTS | `node --version` |
| **npm** | 9+ | 9+ or 10+ | `npm --version` |
| **Docker** | 24+ | Latest Docker Desktop / Engine | `docker --version` |

---

## 2. Quick Start with Docker Compose

The fastest way to run PatchPilot's backend and FalkorDB graph database together:

```bash
# 1. Clone or navigate to the repository
cd patchpilot

# 2. Copy the environment template
cp .env.example .env

# 3. Launch FalkorDB and Backend containers
docker compose up -d

# 4. View real-time logs
docker compose logs -f
```

- **Backend API**: `http://localhost:8000`
- **Swagger Documentation**: `http://localhost:8000/docs`
- **FalkorDB Graph Port**: `127.0.0.1:6379`

To start the frontend alongside Docker backend:
```bash
cd frontend
npm install
npm run dev
```
Open **`http://localhost:5173`** in your browser.

---

## 3. Manual Step-by-Step Setup

If you prefer to run services natively for active development:

### Step 3.1: Start FalkorDB

FalkorDB is a low-latency graph database that speaks the Redis serialization protocol. Run the official FalkorDB image:

```bash
docker run -d \
  --name patchpilot-falkordb \
  -p 127.0.0.1:6379:6379 \
  -v falkordb_data:/data \
  falkordb/falkordb:latest
```

*Verify connectivity:*
```bash
docker exec -it patchpilot-falkordb redis-cli ping
# Expected output: PONG
```

### Step 3.2: Set Up the Backend

1. Navigate to the `backend/` directory:
   ```bash
   cd patchpilot/backend
   ```

2. Create and activate a Python virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Upgrade `pip` and install dependencies:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. Configure environment variables:
   ```bash
   cp .env.example .env
   ```
   *(Default values work out of the box for local development).*

5. Seed the graph with the synthetic benchmark dataset:
   ```bash
   python ../scripts/seed_graph.py --clear
   ```
   *Expected output: Seed complete! (5 vulnerabilities, 8 packages, 4 applications, 5 assets).*

6. Launch the FastAPI server:
   ```bash
   uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```
   Verify at `http://localhost:8000/api/health`.

### Step 3.3: Set Up the Frontend

1. Open a new terminal and navigate to `frontend/`:
   ```bash
   cd patchpilot/frontend
   ```

2. Install npm dependencies:
   ```bash
   npm install
   ```

3. Start the Vite development server:
   ```bash
   npm run dev
   ```
   Visit **`http://localhost:5173`**.

---

## 4. Environment Variables Reference

Create a `.env` file in `patchpilot/backend/.env` (or root `.env`):

```bash
# FalkorDB Graph Connection
FALKORDB_HOST=127.0.0.1
FALKORDB_PORT=6379
FALKORDB_PASSWORD=
FALKORDB_GRAPH=patchpilot

# Service Settings
LOG_LEVEL=INFO
APP_HOST=127.0.0.1
APP_PORT=8000
CORS_ORIGINS=http://localhost:5173,http://localhost:3000

# AI Provider Settings (Optional)
# If left blank, PatchPilot runs in 100% deterministic local mode with zero external calls
LLM_PROVIDER=deterministic
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
```

---

## 5. Seeding and Resetting the Graph

PatchPilot includes a reproducible synthetic benchmark dataset stored in `data/synthetic_data/graph_dataset.json`.

### Option A: Standalone CLI Script
```bash
# Seed or update without deleting existing nodes
python scripts/seed_graph.py

# Wipe the graph and reseed cleanly
python scripts/seed_graph.py --clear

# Seed from a custom dataset file
python scripts/seed_graph.py --file path/to/dataset.json
```

### Option B: REST API
```bash
# Seed via API
curl -X POST "http://localhost:8000/api/seed?clear_first=true"
```

---

## 6. Running Tests

PatchPilot comes with an automated test suite verifying prioritization formulas, API models, and Cypher graph logic:

```bash
cd patchpilot/backend
source venv/bin/activate

# Run all tests
pytest -v

# Run only unit tests (zero database dependency)
pytest tests/test_prioritization.py -v

# Run with test coverage
pytest --cov=app tests/
```

- **Unit Tests**: Pass 100% in isolation with zero external services or database running.
- **Integration Tests**: Automatically execute against FalkorDB if running on port 6379, or gracefully skip when FalkorDB is offline.

To test the frontend build:
```bash
cd patchpilot/frontend
npm run build
```
*(Runs TypeScript type-checks and produces an optimized Vite bundle in `dist/`).*

---

## 7. Troubleshooting FAQ

### Q1: `docker: command not found`
- **Solution**: Install Docker Desktop on macOS/Windows, or `sudo apt-get install docker.io docker-compose-v2` on Ubuntu. If you do not have Docker permissions, run FalkorDB via a remote Redis/FalkorDB host by setting `FALKORDB_HOST` in `.env`.

### Q2: Backend reports `status: "degraded"` on `/api/health`
- **Cause**: The FastAPI backend is running, but FalkorDB is not reachable on port 6379.
- **Solution**: Start the FalkorDB container using `docker run -d -p 127.0.0.1:6379:6379 falkordb/falkordb:latest`. The backend will automatically connect on the next request.

### Q3: `pydantic-core` build failure on Python 3.14
- **Cause**: Older versions of `pydantic-core` attempt to compile with a Rust toolchain when pre-built wheels for new Python versions are unavailable.
- **Solution**: Use `pydantic>=2.14` and `pydantic-settings>=2.16` as specified in `requirements.txt`. Pre-compiled wheels are automatically installed.

### Q4: Port 6379 already in use
- **Cause**: A local Redis instance or another container is occupying port 6379.
- **Solution**: Check the process using `sudo lsof -i :6379` or specify an alternate port in `docker run -p 127.0.0.1:6380:6379` and update `FALKORDB_PORT=6380` in `.env`.

### Q5: CORS error when fetching from frontend
- **Cause**: Frontend origin not in backend whitelist.
- **Solution**: Ensure `CORS_ORIGINS=http://localhost:5173,http://localhost:3000` is present in your backend `.env` file.
