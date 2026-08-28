"""Core CRUD API for tracking scan requests."""

from collections.abc import Generator
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from backend.db.database import Base, SessionLocal, engine
from backend.db.models import Scan
from backend.models.scan import ScanRequest


Base.metadata.create_all(bind=engine)

app = FastAPI(title="Vulnerability Scanner API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan", status_code=status.HTTP_201_CREATED)
def create_scan(request: ScanRequest, db: Session = Depends(get_db)) -> dict[str, str]:
    if not request.authorized:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="must confirm authorization to scan target",
        )
    if not request.target_url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="target_url must start with http:// or https://",
        )

    scan = Scan(target_url=request.target_url)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # TODO: enqueue actual scan job here — wiring point for the orchestration layer
    return {"scan_id": str(scan.id)}


@app.get("/scan/{scan_id}")
def get_scan(scan_id: UUID, db: Session = Depends(get_db)) -> dict:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return _scan_response(scan)


@app.get("/scan/{scan_id}/status")
def get_scan_status(scan_id: UUID, db: Session = Depends(get_db)) -> dict[str, str]:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return {"status": scan.status.value}
