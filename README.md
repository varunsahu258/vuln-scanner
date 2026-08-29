# Vuln Scanner

> **This tool is for authorized security testing and educational purposes only. Only scan targets you own or have explicit permission to test.**

Vuln Scanner is a web application for reviewing the **passive security posture** of a public web target. A React/Vite browser client submits an authorized target to a FastAPI API. Scan work is queued through Redis, processed by a Celery worker, and stored in PostgreSQL for the browser to poll and display.

This project is intentionally **not** a penetration-testing or exploitation framework. Active SQL injection attempts, authentication brute-forcing, payload-based exploitation, destructive/state-modifying checks, and scanning private/internal networks are out of scope by design. This makes the service suitable for careful public deployment when its authorization and rate-limit safeguards are retained.

## LIVE DEMO LINK:
[Vulnerability Scanner]((https://vuln-scanner.varunsahu258.workers.dev/))
## Table of contents

- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick start from a cold clone](#quick-start-from-a-cold-clone)
- [Using the application](#using-the-application)
- [API reference](#api-reference)
- [Scan modules](#scan-modules)
- [Configuration](#configuration)
- [Safeguards](#safeguards)
- [Common development commands](#common-development-commands)
- [Troubleshooting](#troubleshooting)
- [Production deployment](#production-deployment)

## Architecture

```mermaid
flowchart LR
    Browser[React / Vite frontend]
    API[FastAPI API]
    Postgres[(Postgres)]
    Redis[(Redis)]
    Worker[Celery worker]
    Modules[6 passive security modules]

    Browser -->|POST /scan| API
    API -->|create pending scan record| Postgres
    API -->|enqueue scan job| Redis
    Redis -->|deliver job| Worker
    Worker -->|run checks concurrently| Modules
    Worker -->|write status and report| Postgres
    Browser -->|poll GET /scan/{id}/status and GET /scan/{id}| API
    API -->|read scan status/results| Postgres
```

| Component | Location | Responsibility |
| --- | --- | --- |
| Frontend | `frontend/` | Collects a target, requires authorization confirmation, polls status, and renders the report. |
| API | `backend/api/main.py` | Exposes the HTTP contract, validates targets, applies CORS/rate limits, and persists scan requests. |
| Worker | `backend/worker/` | Receives scan jobs from Redis and runs scan modules without blocking API requests. |
| Modules | `backend/modules/` | Performs independent passive checks for headers, TLS, CORS, JWTs, redirects, and reconnaissance. |
| Database | `backend/db/` | Stores scan lifecycle state and the final report in Postgres. |
| Broker | Redis | Carries Celery jobs between the API and worker. |

## Prerequisites

The Docker workflow is the supported path because it starts the browser app, API, worker, broker, and database together.

Install the following before starting:

* [Git](https://git-scm.com/)
* [Docker Desktop](https://www.docker.com/products/docker-desktop/) (or Docker Engine with the Compose plugin)
* Docker Compose v2 (`docker compose version`)

Verify that Docker is running and that the local ports are available:

```bash
docker compose version
docker version
```

The development stack uses these host ports:

| Port | Service | URL |
| --- | --- | --- |
| `3000` | Vite frontend | http://localhost:3000 |
| `8000` | FastAPI backend | http://localhost:8000/health |
| `5432` | Postgres | `postgresql://localhost:5432/vuln_scanner` |
| `6379` | Redis | `redis://localhost:6379/0` |

Stop any local process already using one of these ports, or update the port mapping in `docker-compose.yml` before continuing.

## Quick start from a cold clone

These commands are ordered to ensure the database schema exists **before** the API starts. Run them from a terminal on macOS, Linux, or Windows with a Unix-compatible shell (Git Bash/WSL works on Windows).

### 1. Clone the repository

```bash
git clone <YOUR_REPOSITORY_URL> vuln-scanner
cd vuln-scanner
```

Replace `<YOUR_REPOSITORY_URL>` with your Git remote, for example `https://github.com/your-org/vuln-scanner.git`.

### 2. Create local environment configuration

```bash
cp .env.example .env
```

The supplied `.env.example` values are safe **only for local development** and connect the Compose services by their Docker service names. Do not commit `.env`.

For a clean local startup, keep `DATABASE_URL` and the Postgres variables aligned as shown below:

```dotenv
POSTGRES_DB=vuln_scanner
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
DATABASE_URL=postgresql+psycopg2://postgres:postgres@postgres:5432/vuln_scanner
REDIS_URL=redis://redis:6379/0
ALLOWED_ORIGINS=http://localhost:3000
VITE_API_URL=http://localhost:8000
```

### 3. Start Postgres and Redis

```bash
docker compose up -d postgres redis
docker compose ps
```

Wait until both services show `running` (and `healthy` where reported). You can explicitly inspect their health with:

```bash
docker compose ps
docker compose logs --tail=50 postgres redis
```

### 4. Apply database migrations

Run migrations once before starting the API and worker:

```bash
docker compose run --rm backend alembic upgrade head
```

Expected final output includes an Alembic upgrade to revision `20260828_02`. To confirm the schema is present:

```bash
docker compose exec postgres psql -U postgres -d vuln_scanner -c '\dt'
```

The output should include a `scans` table.

### 5. Build and start the application services

```bash
docker compose up --build -d backend celery-worker frontend
docker compose ps
```

All five services (`backend`, `celery-worker`, `frontend`, `postgres`, and `redis`) should be running. Tail logs if any service exits:

```bash
docker compose logs -f backend celery-worker frontend
```

### 6. Verify the stack

Check the API health endpoint:

```bash
curl --fail http://localhost:8000/health
```

Expected response:

```json
{"status":"ok"}
```

Then open http://localhost:3000 in a browser. The page should display the **VulnScan** scan form.

### 7. Stop or reset the stack

Stop containers while retaining database data:

```bash
docker compose down
```

Remove containers **and all local Postgres data** to return to a truly clean state:

```bash
docker compose down -v
```

After `down -v`, repeat steps 3–6, including migrations.

## Using the application

1. Open http://localhost:3000.
2. Enter an `http://` or `https://` public target that you own or are explicitly authorized to assess.
3. Optionally open **Advanced** and paste a JWT for passive JWT analysis.
4. Select **I confirm I have permission to scan this target**. The submit button remains disabled until both a target and consent are supplied.
5. Start the scan. The frontend polls every two seconds and shows the report when the worker has completed it.

### Standalone frontend demo mode

To develop or demonstrate only the interface without an API, set this in `.env` before starting the frontend:

```dotenv
VITE_MOCK_API=true
```

Recreate the frontend container so Vite receives the new value:

```bash
docker compose up --build -d frontend
```

Mock mode returns a deterministic in-progress response followed by a completed sample report. Set `VITE_MOCK_API=false` to resume calls to the API.

## API reference

The API base URL is `http://localhost:8000` in the default Docker setup. FastAPI also exposes interactive API documentation at http://localhost:8000/docs.

### `GET /health`

Returns API availability.

```bash
curl --fail http://localhost:8000/health
```

### `POST /scan`

Creates a pending scan request. The caller must affirm authorization. Private addresses and localhost are rejected by SSRF protection.

```bash
curl --request POST http://localhost:8000/scan \
  --header 'Content-Type: application/json' \
  --data '{
    "target_url": "https://example.com",
    "jwt_token": null,
    "authorized": true
  }'
```

Successful response (`201 Created`):

```json
{"scan_id":"00000000-0000-0000-0000-000000000000"}
```

Validation/authorization/SSRF rejection returns `400` with a `detail` string. Per-IP request limits return `429` with a `detail` string.

### `GET /scan/{scan_id}/status`

Returns one of `pending`, `running`, `completed`, or `failed`:

```bash
curl http://localhost:8000/scan/<scan_id>/status
```

### `GET /scan/{scan_id}`

Returns the persisted scan record and, after completion, its module report:

```bash
curl http://localhost:8000/scan/<scan_id>
```

## Scan modules

The worker combines these six independent modules into one report:

| Module | Source | What it checks |
| --- | --- | --- |
| HTTP security headers | `backend/modules/headers.py` | Recommended browser-facing response headers. |
| TLS | `backend/modules/tls.py` | HTTPS availability, certificate validity, and transport configuration. |
| CORS | `backend/modules/cors.py` | Potentially unsafe origin and credential policy combinations. |
| JWT analysis | `backend/modules/jwt_check.py` | Properties of an optionally supplied JWT; skipped when no token is supplied. |
| Open redirect | `backend/modules/redirect.py` | Redirect behavior that could send users to an untrusted destination, without target-state changes. |
| Passive subdomain reconnaissance | `backend/modules/recon.py` | Public DNS and subdomain information without active enumeration attacks. |

## Configuration

Copy `.env.example` to `.env`; it documents every value consumed by Compose, the backend, or the Vite frontend.

| Variable | Required | Local example | Purpose |
| --- | --- | --- | --- |
| `DATABASE_URL` | Yes | `postgresql+psycopg2://postgres:postgres@postgres:5432/vuln_scanner` | SQLAlchemy connection string used by API and worker. |
| `REDIS_URL` | Yes | `redis://redis:6379/0` | Celery broker/result-backend URL. |
| `ALLOWED_ORIGINS` | Yes | `http://localhost:3000` | Comma-separated CORS origins allowed to call the API. |
| `RATE_LIMIT_SCAN_PER_HOUR` | Yes | `5` | Scan submissions allowed per client IP per hour. |
| `RATE_LIMIT_READ_PER_HOUR` | Yes | `60` | Read/status requests allowed per client IP per hour. |
| `VITE_API_URL` | Yes | `http://localhost:8000` | API URL used by the browser client; embedded at frontend build time for production. |
| `VITE_MOCK_API` | No | `false` | Set to `true` to use canned frontend responses. |
| `POSTGRES_DB` | Self-hosted only | `vuln_scanner` | Postgres database name. |
| `POSTGRES_USER` | Self-hosted only | `postgres` | Postgres username. |
| `POSTGRES_PASSWORD` | Self-hosted only | `postgres` | Postgres password. Use a strong secret outside development. |
| `BACKEND_IMAGE` | Production overlay | `ghcr.io/your-org/vuln-scanner-backend:latest` | Pre-built API/worker image reference. |
| `FRONTEND_IMAGE` | Production overlay | `ghcr.io/your-org/vuln-scanner-frontend:latest` | Pre-built Nginx static frontend image reference. |
| `FRONTEND_PORT` | Production overlay | `3000` | Host port mapped to the static frontend container. |

When changing `VITE_API_URL` for a production image, build the frontend with the value supplied as a build argument:

```bash
docker build \
  --build-arg VITE_API_URL=https://api.scanner.example \
  --target production \
  --tag ghcr.io/your-org/vuln-scanner-frontend:latest \
  frontend
```

## Safeguards

* **Terms-of-use gate:** the browser form requires an explicit statement that the requester has permission to scan the target.
* **Rate limiting:** scan creation defaults to **5 scans per IP per hour**; read endpoints have their own configurable limit.
* **SSRF protection:** target validation blocks localhost and private/reserved address ranges before workers can connect to them.
* **Passive-only methodology:** the scanner does not run SQL injection payloads, credential attacks, or state-modifying checks.
* **Structured request logging:** API request outcomes are logged for traceability and operational monitoring.

These controls are complementary. Do not remove the authorization gate, SSRF protection, or rate limits when exposing the service to the internet.

## Common development commands

| Task | Command |
| --- | --- |
| Start the complete stack | `docker compose up --build` |
| Start in background | `docker compose up --build -d` |
| Follow all logs | `docker compose logs -f` |
| API logs only | `docker compose logs -f backend` |
| Worker logs only | `docker compose logs -f celery-worker` |
| Run migrations | `docker compose run --rm backend alembic upgrade head` |
| Run backend tests | `docker compose run --rm backend pytest` |
| Run frontend tests | `docker compose run --rm frontend npm test` |
| Build frontend production assets | `docker compose run --rm frontend npm run build` |
| Stop stack | `docker compose down` |
| Reset all local data | `docker compose down -v` |

## Troubleshooting

### `docker compose` cannot connect to Docker

Start Docker Desktop (or the Docker daemon) and retry `docker version`. On Linux, ensure your account can access the Docker socket.

### A service cannot bind a port

Find the conflicting local process, stop it, then retry. Alternatively, change the host-side mapping in `docker-compose.yml`, for example `"3001:3000"` for the frontend. If the frontend port changes, update `ALLOWED_ORIGINS` to match its new browser origin.

### The backend reports database connection failures

Confirm the database is healthy:

```bash
docker compose ps postgres
docker compose logs --tail=100 postgres
```

Confirm `.env` uses the Docker hostname `postgres` in `DATABASE_URL`, not `localhost`. Then rerun the migration command from step 4.

### The UI cannot call the API (CORS error)

Set `ALLOWED_ORIGINS` to the exact frontend origin, including scheme and port, such as `http://localhost:3000`. For multiple origins, use a comma-separated list. Restart the backend after changing it:

```bash
docker compose up -d --force-recreate backend
```

### A scan remains pending

Check the worker connection and logs:

```bash
docker compose ps celery-worker redis
docker compose logs --tail=200 celery-worker redis
```

Verify `REDIS_URL=redis://redis:6379/0` is configured identically for the backend and worker, and verify the worker is running before submitting a scan.

### Start over completely

```bash
docker compose down -v --remove-orphans
docker compose up -d postgres redis
docker compose run --rm backend alembic upgrade head
docker compose up --build -d backend celery-worker frontend
```

## Production deployment

`docker-compose.prod.yml` is an overlay for images that have already been built and published. It intentionally removes the frontend development bind mount and serves static Vite output through Nginx rather than the Vite development server.

### Build and publish images

Build the backend once; use the same image for both API and worker processes:

```bash
docker build -f backend/Dockerfile -t ghcr.io/your-org/vuln-scanner-backend:latest .
docker push ghcr.io/your-org/vuln-scanner-backend:latest
```

Build the frontend with the public API URL that browsers will use:

```bash
docker build \
  --build-arg VITE_API_URL=https://api.scanner.example \
  --target production \
  -t ghcr.io/your-org/vuln-scanner-frontend:latest \
  frontend
docker push ghcr.io/your-org/vuln-scanner-frontend:latest
```

Set strong, deployment-specific values for `DATABASE_URL`, `REDIS_URL`, `ALLOWED_ORIGINS`, rate limits, image names, and (if self-hosting Postgres) `POSTGRES_PASSWORD`. Do not put database or Redis URLs in `VITE_API_URL`; that value is public browser configuration.

### Railway or Render

Use managed Postgres and Redis add-ons/services rather than self-hosting those data services where possible.

1. Create a **web service** from the backend image. Use the default command: `uvicorn backend.api.main:app --host 0.0.0.0 --port 8000`.
2. Create a separate **worker service** from the same backend image with: `celery -A backend.worker.celery_app worker --loglevel=info`.
3. Provision managed Postgres and Redis. Set `DATABASE_URL` and `REDIS_URL` on **both** web and worker services.
4. Set `ALLOWED_ORIGINS`, `RATE_LIMIT_SCAN_PER_HOUR`, and `RATE_LIMIT_READ_PER_HOUR` on the web service; use the same values on the worker for consistent configuration.
5. Run `alembic upgrade head` as a one-off release/pre-deploy command using the backend image and production `DATABASE_URL`.
6. Deploy the frontend image as a static/container service, building it with `VITE_API_URL` set to the public backend URL. Add its public URL to `ALLOWED_ORIGINS`.

For self-hosted production dependencies, populate the production image variables in `.env` and run:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile self-hosted up -d
```

## License

This project is licensed under the [MIT License](LICENSE).
