"""Core CRUD API for tracking scan requests."""

# This is the existing CRUD API, not a replacement demo; the protections below
# are intentionally layered around its real scan-creation behavior.

from collections.abc import Generator
import logging
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from backend.config import settings
from backend.db.database import Base, SessionLocal, engine
from backend.db.models import Scan
from backend.logging_config import configure_logging
from backend.models.scan import ScanRequest
from backend.security.ssrf_guard import is_safe_target


Base.metadata.create_all(bind=engine)
configure_logging()
logger = logging.getLogger("backend")
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="Vulnerability Scanner API")
app.state.limiter = limiter
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _log_scan_request(
    request: Request, target_url: str | None, outcome: str, scan_id: str | None = None
) -> None:
    source_ip = request.client.host if request.client else "unknown"
    logger.info(
        "scan_request",
        extra={
            "source_ip": source_ip,
            "target_url": target_url,
            "outcome": outcome,
            "scan_id": scan_id,
        },
    )


async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """Return the API's stable rate-limit response and log rejected scan posts."""
    target_url = None
    if request.method == "POST" and request.url.path == "/scan":
        try:
            target_url = (await request.json()).get("target_url")
        except (ValueError, AttributeError):
            pass
        _log_scan_request(request, target_url, "rate_limited")
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": "Rate limit exceeded, try again later"},
    )


app.add_exception_handler(RateLimitExceeded, rate_limit_handler)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _scan_response(scan: Scan) -> dict:
    return {
        "id": str(scan.id),
        "target_url": scan.target_url,
        "status": scan.status.value,
        "created_at": scan.created_at,
        "completed_at": scan.completed_at,
        "results": scan.results,
    }


@app.get("/health")
@limiter.limit(f"{settings.rate_limit_read_per_hour}/hour")
def health(request: Request) -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan", status_code=status.HTTP_201_CREATED)
@limiter.limit(f"{settings.rate_limit_scan_per_hour}/hour")
def create_scan(
    request: Request, scan_request: ScanRequest, db: Session = Depends(get_db)
) -> dict[str, str]:
    if not scan_request.authorized:
        _log_scan_request(request, scan_request.target_url, "rejected_unauthorized")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="must confirm authorization to scan target",
        )
    if not scan_request.target_url.startswith(("http://", "https://")):
        _log_scan_request(request, scan_request.target_url, "rejected_ssrf")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="target_url must start with http:// or https://",
        )

    safe_target, reason = is_safe_target(scan_request.target_url)
    if not safe_target:
        _log_scan_request(request, scan_request.target_url, "rejected_ssrf")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=reason)

    scan = Scan(target_url=scan_request.target_url, jwt_token=scan_request.jwt_token)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # TODO: enqueue actual scan job here — wiring point for the orchestration layer
    _log_scan_request(request, scan_request.target_url, "accepted", str(scan.id))
    return {"scan_id": str(scan.id)}


@app.get("/scan/{scan_id}")
@limiter.limit(f"{settings.rate_limit_read_per_hour}/hour")
def get_scan(request: Request, scan_id: UUID, db: Session = Depends(get_db)) -> dict:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return _scan_response(scan)


@app.get("/scan/{scan_id}/status")
@limiter.limit(f"{settings.rate_limit_read_per_hour}/hour")
def get_scan_status(
    request: Request, scan_id: UUID, db: Session = Depends(get_db)
) -> dict[str, str]:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return {"status": scan.status.value}
