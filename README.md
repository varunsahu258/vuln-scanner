# Vuln Scanner

> **This tool is for authorized security testing and educational purposes only. Only scan targets you own or have explicit permission to test.**

Vuln Scanner is a passive security-posture scanner for public-facing web applications. It reviews headers, TLS, CORS, JWTs, open redirects, and publicly available subdomain information, then presents a clear report of the observed security posture.

## Scope and safety

This is **not** a penetration-testing or exploit tool. It deliberately excludes active SQL injection testing, authentication brute-forcing, and any check that modifies target state. Those exclusions, together with the safeguards below, are intentional so the service can be deployed publicly without performing intrusive testing.

## Architecture

```mermaid
flowchart LR
    F[React / Vite frontend] -->|POST /scan| A[FastAPI API]
    A -->|create pending scan record| P[(Postgres)]
    A -->|enqueue scan job| R[(Redis)]
    W[Celery worker] -->|consume job| R
    W -->|run 6 modules concurrently| M[Headers · TLS · CORS · JWT · Redirect · Recon]
    W -->|write status and results| P
    F -->|poll GET /scan/{id}/status and GET /scan/{id}| A
    A -->|read status and results| P
```

The FastAPI application in `backend/api/main.py` exposes `POST /scan`, `GET /scan/{id}`, `GET /scan/{id}/status`, and `GET /health`. It creates scan records in Postgres (`backend/db/`) and sends work through Redis to the Celery worker (`backend/worker/`). The worker runs the independent modules concurrently and persists final results. The React/Vite application (`frontend/`) submits a scan and polls the API until the result is ready.

## Local setup

1. Clone the repository and enter it:
   ```bash
   git clone <repository-url> vuln-scanner
   cd vuln-scanner
   ```
2. Create local configuration:
   ```bash
   cp .env.example .env
   ```
   The example values connect the Compose services together. Change `POSTGRES_PASSWORD` before exposing the stack outside local development, and ensure `DATABASE_URL` uses the same password.
3. Build and start the services:
   ```bash
   docker compose up --build
   ```
4. In another terminal, apply the database migrations:
   ```bash
   docker compose exec backend alembic upgrade head
   ```
5. Open [http://localhost:3000](http://localhost:3000). The API health endpoint is [http://localhost:8000/health](http://localhost:8000/health).

For standalone frontend demos, set `VITE_MOCK_API=true` in `.env` before starting the frontend. The browser client will then return a canned in-progress scan and report without calling an API.

## Scan modules

* **HTTP security headers** (`backend/modules/headers.py`) — checks recommended browser-facing HTTP response headers.
* **TLS** (`backend/modules/tls.py`) — inspects HTTPS availability, certificate properties, and transport configuration.
* **CORS** (`backend/modules/cors.py`) — evaluates cross-origin response policy for unsafe origin or credential combinations.
* **JWT analysis** (`backend/modules/jwt_check.py`) — passively examines a user-supplied token and reports common validation concerns; it is skipped when no token is supplied.
* **Open redirect** (`backend/modules/redirect.py`) — detects redirect behavior that may send users to untrusted destinations without altering target state.
* **Passive subdomain reconnaissance** (`backend/modules/recon.py`) — collects publicly available DNS/subdomain information without active enumeration attacks.

## Safeguards

* **Terms-of-use gate:** the frontend requires the requester to confirm they have permission to scan the target before a scan can be submitted.
* **Rate limiting:** the API limits scans to **5 scans per IP per hour** by default; read/status endpoints have a separate configurable hourly limit.
* **SSRF protection:** target validation blocks localhost and private/reserved IP ranges so workers cannot be used to reach internal services.
* **Passive-only checks:** no SQL injection payloads, credential attacks, or state-modifying requests are sent.
* **Structured request logging:** the API records structured request events to support auditability and operational monitoring.

## Deployment (Railway or Render)

Railway and Render can host this architecture using managed Postgres and Redis add-ons/services rather than self-hosting the `postgres` and `redis` containers.

1. Build and publish the backend image from `backend/Dockerfile` and the static frontend image from `frontend/Dockerfile`. Pass the public API URL as the `VITE_API_URL` build argument when building the frontend because Vite embeds it at build time.
2. Create a **web service** from the backend image. Its start command is the Dockerfile default (`uvicorn backend.api.main:app --host 0.0.0.0 --port 8000`).
3. Create a separate **worker service** from the same backend image with this command:
   ```bash
   celery -A backend.worker.celery_app worker --loglevel=info
   ```
4. Provision managed Postgres and Redis, then set `DATABASE_URL` and `REDIS_URL` on both the web and worker services. Set `ALLOWED_ORIGINS`, `RATE_LIMIT_SCAN_PER_HOUR`, and `RATE_LIMIT_READ_PER_HOUR` on the web service (setting them on both is harmless and keeps configuration consistent).
5. Deploy the static frontend image to a static site/CDN-capable service or container service. Configure the frontend build with `VITE_API_URL` pointing at the public backend URL, and include the frontend's public URL in `ALLOWED_ORIGINS`.
6. Run `alembic upgrade head` as a release/pre-deploy command using the backend image and `DATABASE_URL`. Do not publish the self-hosted database password or broker URL in client-side configuration.

`docker-compose.prod.yml` is a production overlay for pre-built images. Set `BACKEND_IMAGE`, `FRONTEND_IMAGE`, `FRONTEND_PORT`, and the runtime variables in `.env`, then use it only when self-hosting the supporting services:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile self-hosted up -d
```

## Environment variables

Copy `.env.example` to `.env` for a documented list of all runtime, frontend-build, self-hosted database, and Compose image variables. Never commit `.env` or production credentials.
