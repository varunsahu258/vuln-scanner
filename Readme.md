<div align="center">

# 🛡️ VulnScan

### Passive web security posture scanner

**Point it at a site you own. Get an A–F security report in seconds — no exploits, no payloads, no risk.**

<br>

[![Live Demo](https://img.shields.io/badge/🚀_Live_Demo-Try_it_now-2563eb?style=for-the-badge)](https://vuln-scanner.varunsahu258.workers.dev/)

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-20232A?style=flat-square&logo=react&logoColor=61DAFB)
![Vite](https://img.shields.io/badge/Vite-646CFF?style=flat-square&logo=vite&logoColor=white)
![Celery](https://img.shields.io/badge/Celery-37814A?style=flat-square&logo=celery&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=flat-square&logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-DC382D?style=flat-square&logo=redis&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat-square&logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

<br>

[Features](#-features) ·
[How it works](#-how-it-works) ·
[Quick start](#-quick-start) ·
[API](#-api-reference) ·
[Configuration](#%EF%B8%8F-configuration) ·
[Deploy](#-production-deployment)

</div>

---

> [!IMPORTANT]
> **For authorized testing and education only.** Only scan targets you own or have explicit permission to test.

## 📖 About

**VulnScan** is a web app that reviews the **passive security posture** of a public website. A React frontend submits a target to a FastAPI backend, a Celery worker runs six independent checks in parallel, and the results are stored in PostgreSQL and shown as a graded report.

It is deliberately **not** a penetration-testing or exploitation framework. These are out of scope by design:

| ❌ Not included | ✅ What it does instead |
|---|---|
| SQL injection attempts | Reads public response headers and certificates |
| Credential brute-forcing | Inspects only a JWT *you* supply |
| Payload-based exploitation | Sends ordinary, non-destructive requests |
| State-modifying checks | Leaves the target unchanged |
| Scanning private networks | Blocks localhost and private IP ranges |

That makes it suitable for careful public deployment, as long as its safeguards stay in place.

---

## ✨ Features

<table>
<tr>
<td width="50%" valign="top">

### 🔍 Six passive scan modules
Headers, TLS, CORS, JWT, open redirect and subdomain reconnaissance, run concurrently.

### 🎓 Letter-grade reports
Every module gets an **A–F** score, and the report shows an overall grade based on the weakest module.

### ⚡ Async by design
Scans run in a Celery worker, so the API never blocks. The UI polls and updates live.

</td>
<td width="50%" valign="top">

### 🔒 Built-in safeguards
Consent gate, DNS-aware SSRF protection, per-IP rate limiting and structured request logging.

### 🎨 Clean React UI
Expandable module cards, color-coded severity badges and a progress indicator.

### 🐳 One-command stack
Docker Compose starts the frontend, API, worker, Postgres and Redis together.

</td>
</tr>
</table>

---

## 🔬 Scan Modules

| | Module | What it checks | Source |
|:---:|---|---|---|
| 🧱 | **HTTP Headers** | CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy and other browser-facing headers | `modules/headers.py` |
| 🔐 | **TLS** | HTTPS availability, certificate validity, hostname match, self-signed certificates | `modules/tls.py` |
| 🌐 | **CORS** | Unsafe origin and credential policy combinations | `modules/cors.py` |
| 🎟️ | **JWT** | Weak signing secrets, sensitive claims, expiry. *Skipped if no token is supplied* | `modules/jwt_check.py` |
| ↪️ | **Open Redirect** | Redirects that could send users to an untrusted destination | `modules/redirect.py` |
| 🗺️ | **Subdomain Recon** | Public certificate data and DNS, including dangling CNAMEs | `modules/recon.py` |

### 📊 Grading

| Grade | Meaning |
|:---:|---|
| 🟢 **A** | No meaningful issues found |
| 🟡 **B** | Minor issues |
| 🟠 **C – D** | One or more high-severity findings |
| 🔴 **F** | Critical failure, such as an unreachable or invalid TLS setup |
| ⚪ **N/A** | Module skipped, for example JWT with no token |

Findings carry a severity of `info`, `low`, `medium` or `high`. Exact scoring rules are defined per module in `backend/modules/`.

---

## 🏗️ How It Works

```mermaid
flowchart LR
    Browser["🖥️ React / Vite<br/>frontend"]
    API["⚙️ FastAPI<br/>API"]
    Postgres[("🐘 Postgres")]
    Redis[("🔴 Redis")]
    Worker["👷 Celery<br/>worker"]
    Modules["🔬 6 passive<br/>modules"]

    Browser -->|"POST /scan"| API
    API -->|"create pending scan"| Postgres
    API -->|"enqueue job"| Redis
    Redis -->|"deliver job"| Worker
    Worker -->|"run concurrently"| Modules
    Worker -->|"save status + report"| Postgres
    Browser -->|"poll status / report"| API
    API -->|"read results"| Postgres
```

| Component | Location | Role |
|---|---|---|
| 🖥️ **Frontend** | `frontend/` | Collects the target, requires consent, polls status, renders the report |
| ⚙️ **API** | `backend/api/main.py` | Validates targets, applies CORS and rate limits, persists scan requests |
| 👷 **Worker** | `backend/worker/` | Runs scan modules off the request path (60 s time limit per scan) |
| 🔬 **Modules** | `backend/modules/` | Independent passive checks |
| 🛡️ **Security** | `backend/security/` | SSRF guard |
| 🗄️ **Database** | `backend/db/` | Alembic migrations, scan lifecycle and report storage |

---

## 🛡️ Safeguards

| Safeguard | How it works |
|---|---|
| ✋ **Consent gate** | The form and API both require an explicit authorization confirmation |
| 🚧 **SSRF protection** | Resolves the hostname and rejects localhost, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `::1` and `fc00::/7` |
| ⏱️ **Rate limiting** | Defaults to **5 scans** and **60 reads** per IP per hour (configurable) |
| 🔇 **Passive only** | No attack payloads, credential attacks or state changes |
| 📋 **Request logging** | Structured logs for traceability |

> [!WARNING]
> These controls work together. Do not remove the consent gate, SSRF protection or rate limits when exposing the service to the internet.

---

## 🚀 Quick Start

### Prerequisites

- [Git](https://git-scm.com/)
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) or Docker Engine with Compose v2

| Port | Service | URL |
|:---:|---|---|
| `3000` | Frontend | http://localhost:3000 |
| `8000` | API | http://localhost:8000/health |
| `5432` | Postgres | `postgresql://localhost:5432/vuln_scanner` |
| `6379` | Redis | `redis://localhost:6379/0` |

### Run it

```bash
# 1️⃣ Clone
git clone <YOUR_REPOSITORY_URL> vuln-scanner
cd vuln-scanner

# 2️⃣ Configure (safe for local development only)
cp .env.example .env

# 3️⃣ Start the database and broker
docker compose up -d postgres redis

# 4️⃣ Apply migrations (before starting the API!)
docker compose run --rm backend alembic upgrade head

# 5️⃣ Start the app
docker compose up --build -d backend celery-worker frontend

# 6️⃣ Verify
curl --fail http://localhost:8000/health
```

Expected health response: `{"status":"ok"}`. Then open **http://localhost:3000** 🎉

<details>
<summary><b>📦 Stop or reset the stack</b></summary>

<br>

```bash
docker compose down        # stop, keep data
docker compose down -v     # stop and delete all local Postgres data
```

After `down -v`, repeat steps 3 to 6, including migrations.

</details>

### Using the app

1. Open http://localhost:3000
2. Enter an `http://` or `https://` URL you own or are authorized to assess
3. *(Optional)* open **Advanced** and paste a JWT for passive analysis
4. Tick **I confirm I have permission to scan this target**
5. Start the scan. The UI polls every 2 seconds and shows the report when done

<details>
<summary><b>🎭 Frontend-only demo mode</b></summary>

<br>

To develop or demo the UI without the API, set this in `.env`:

```dotenv
VITE_MOCK_API=true
```

Then recreate the frontend:

```bash
docker compose up --build -d frontend
```

Mock mode returns an in-progress response followed by a sample report. Set it back to `false` to use the real API.

</details>

---

## 📡 API Reference

Base URL: `http://localhost:8000` · Interactive docs: [`/docs`](http://localhost:8000/docs)

| Method | Endpoint | Description |
|:---:|---|---|
| `GET` | `/health` | API availability |
| `POST` | `/scan` | Create a pending scan |
| `GET` | `/scan/{scan_id}/status` | `pending`, `running`, `completed` or `failed` |
| `GET` | `/scan/{scan_id}` | Scan record and, once complete, the full report |

<details>
<summary><b>📨 Example: create a scan</b></summary>

<br>

```bash
curl --request POST http://localhost:8000/scan \
  --header 'Content-Type: application/json' \
  --data '{
    "target_url": "https://example.com",
    "jwt_token": null,
    "authorized": true
  }'
```

`201 Created`:

```json
{ "scan_id": "00000000-0000-0000-0000-000000000000" }
```

| Status | Meaning |
|:---:|---|
| `400` | Validation, authorization or SSRF rejection (see `detail`) |
| `429` | Per-IP rate limit exceeded |

</details>

<details>
<summary><b>🧾 Report shape</b></summary>

<br>

Each module returns a result in this form:

```json
{
  "module_name": "headers",
  "score": "B",
  "findings": [
    {
      "check_name": "Content-Security-Policy",
      "severity": "high",
      "passed": false,
      "detail": "Header is missing."
    }
  ]
}
```

`score` is one of `A` to `F`, and `severity` is one of `info`, `low`, `medium` or `high`.

</details>

---

## ⚙️ Configuration

Copy `.env.example` to `.env`. It documents every variable.

| Variable | Local example | Purpose |
|---|---|---|
| `DATABASE_URL` | `postgresql+psycopg2://postgres:postgres@postgres:5432/vuln_scanner` | Connection string for API and worker |
| `REDIS_URL` | `redis://redis:6379/0` | Celery broker and result backend |
| `ALLOWED_ORIGINS` | `http://localhost:3000` | Comma-separated CORS origins |
| `RATE_LIMIT_SCAN_PER_HOUR` | `5` | Scans per IP per hour |
| `RATE_LIMIT_READ_PER_HOUR` | `60` | Read requests per IP per hour |
| `VITE_API_URL` | `http://localhost:8000` | API URL used by the browser (baked in at build time) |
| `VITE_MOCK_API` | `false` | Use canned frontend responses |
| `POSTGRES_DB` / `USER` / `PASSWORD` | `vuln_scanner` / `postgres` / `postgres` | Self-hosted Postgres. **Use a strong password outside development** |
| `BACKEND_IMAGE`, `FRONTEND_IMAGE`, `FRONTEND_PORT` | | Production overlay only |

> [!CAUTION]
> `VITE_API_URL` is public browser configuration. Never put database or Redis URLs in it.

---

## 🧰 Development Commands

| Task | Command |
|---|---|
| Start everything | `docker compose up --build` |
| Run in background | `docker compose up --build -d` |
| Follow all logs | `docker compose logs -f` |
| API logs | `docker compose logs -f backend` |
| Worker logs | `docker compose logs -f celery-worker` |
| Run migrations | `docker compose run --rm backend alembic upgrade head` |
| 🧪 Backend tests | `docker compose run --rm backend pytest` |
| 🧪 Frontend tests | `docker compose run --rm frontend npm test` |
| Build frontend assets | `docker compose run --rm frontend npm run build` |

The backend test suite covers every scan module, the SSRF guard, the scan endpoints, the pipeline and hardening integration. The frontend uses Vitest with Testing Library.

---

## 🗂️ Project Structure

<details>
<summary><b>Expand the file tree</b></summary>

```
vuln-scanner/
├── backend/
│   ├── api/                  # FastAPI app and routes
│   ├── modules/              # headers, tls, cors, jwt_check, redirect, recon
│   │   └── wordlists/        # Weak JWT secret list
│   ├── security/             # SSRF guard
│   ├── worker/               # Celery app and scan task
│   ├── db/                   # SQLAlchemy models and Alembic migrations
│   ├── models/               # Shared Pydantic models
│   ├── tests/                # Pytest suite
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── components/       # ScanForm, ScanProgress, ReportView, ModuleCard, FindingRow
│   │   ├── hooks/            # useScanPolling
│   │   └── api/              # API client
│   ├── Dockerfile
│   └── nginx.conf
├── docker-compose.yml        # Development stack
├── docker-compose.prod.yml   # Production overlay
├── alembic.ini
└── .env.example
```

</details>

---

## 🩺 Troubleshooting

<details>
<summary><b>🐳 Docker can't connect</b></summary>

<br>

Start Docker Desktop (or the daemon) and check `docker version`. On Linux, make sure your user can access the Docker socket.

</details>

<details>
<summary><b>🔌 A port is already in use</b></summary>

<br>

Stop the conflicting process, or change the host-side mapping in `docker-compose.yml`, for example `"3001:3000"`. If the frontend port changes, update `ALLOWED_ORIGINS` to match.

</details>

<details>
<summary><b>🗄️ Database connection failures</b></summary>

<br>

```bash
docker compose ps postgres
docker compose logs --tail=100 postgres
```

`DATABASE_URL` must use the Docker hostname `postgres`, not `localhost`. Then re-run the migration step.

</details>

<details>
<summary><b>🚫 CORS error in the browser</b></summary>

<br>

Set `ALLOWED_ORIGINS` to the exact frontend origin, including scheme and port. Then restart the backend:

```bash
docker compose up -d --force-recreate backend
```

</details>

<details>
<summary><b>⏳ A scan stays "pending"</b></summary>

<br>

```bash
docker compose ps celery-worker redis
docker compose logs --tail=200 celery-worker redis
```

Check that `REDIS_URL` is identical for the backend and worker, and that the worker is running.

</details>

<details>
<summary><b>🔄 Start over completely</b></summary>

<br>

```bash
docker compose down -v --remove-orphans
docker compose up -d postgres redis
docker compose run --rm backend alembic upgrade head
docker compose up --build -d backend celery-worker frontend
```

</details>

---

## 🌍 Production Deployment

`docker-compose.prod.yml` is an overlay for pre-built images. It drops the dev bind mount and serves the static Vite build through Nginx.

### 1. Build and publish images

```bash
# Backend (used for both API and worker)
docker build -f backend/Dockerfile -t ghcr.io/your-org/vuln-scanner-backend:latest .
docker push ghcr.io/your-org/vuln-scanner-backend:latest

# Frontend (bake in the public API URL)
docker build \
  --build-arg VITE_API_URL=https://api.scanner.example \
  --target production \
  -t ghcr.io/your-org/vuln-scanner-frontend:latest \
  frontend
docker push ghcr.io/your-org/vuln-scanner-frontend:latest
```

### 2. Self-hosted

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile self-hosted up -d
```

### 3. Railway / Render

Prefer managed Postgres and Redis.

| Step | Action |
|:---:|---|
| 1 | Create a **web service** from the backend image: `uvicorn backend.api.main:app --host 0.0.0.0 --port 8000` |
| 2 | Create a **worker service** from the same image: `celery -A backend.worker.celery_app worker --loglevel=info` |
| 3 | Set `DATABASE_URL` and `REDIS_URL` on **both** services |
| 4 | Set `ALLOWED_ORIGINS` and the rate limits (use the same values on the worker) |
| 5 | Run `alembic upgrade head` as a one-off pre-deploy command |
| 6 | Deploy the frontend image, built with `VITE_API_URL` pointing at the backend, and add its URL to `ALLOWED_ORIGINS` |

---

## 🤝 Contributing

Contributions are welcome. Keep the project's scope in mind: **passive checks only**. Please run the backend and frontend tests before opening a pull request.

## 📄 License

Released under the [MIT License](LICENSE).

---

<div align="center">

**Scan responsibly. Only test what you own or have permission to test.** 🛡️

</div>
