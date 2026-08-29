"""Celery tasks that coordinate independent scan modules."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import logging
from uuid import UUID

from backend.db.database import SessionLocal
from backend.db.models import Scan, ScanStatus
from backend.models.scan import Finding, ModuleResult, ScanReport
from backend.modules.cors import check_cors
from backend.modules.headers import check_headers
from backend.modules.jwt_check import check_jwt
from backend.modules.recon import check_subdomain_recon
from backend.modules.redirect import check_open_redirect
from backend.modules.tls import check_tls

from .celery_app import celery_app


logger = logging.getLogger(__name__)
_GRADE_PRIORITY = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}


def _as_module_result(result: object) -> ModuleResult:
    """Normalize scanner results to the API-facing Pydantic model."""
    if isinstance(result, ModuleResult):
        return result
    if hasattr(result, "model_dump"):
        return ModuleResult.model_validate(result.model_dump())
    return ModuleResult.model_validate(result)


def _overall_grade(module_results: list[ModuleResult]) -> str:
    gradable_results = [
        result.score for result in module_results if result.score in _GRADE_PRIORITY
    ]
    return max(gradable_results, key=_GRADE_PRIORITY.__getitem__) if gradable_results else "A"


def _skipped_jwt_result() -> ModuleResult:
    return ModuleResult(
        module_name="jwt",
        score="N/A",
        findings=[
            Finding(
                check_name="jwt_check",
                severity="info",
                passed=True,
                detail="JWT check skipped - no token provided",
            )
        ],
    )


@celery_app.task(bind=True, time_limit=60)
def run_scan(self, scan_id: str) -> None:
    """Run independent scanners in parallel and persist a unified report."""
    db = SessionLocal()
    try:
        try:
            scan_uuid = UUID(scan_id)
        except ValueError:
            logger.warning("Invalid scan id supplied to scan worker: %s", scan_id)
            return

        scan = db.get(Scan, scan_uuid)
        if scan is None:
            logger.info("Scan %s was not found; no work to perform", scan_id)
            return

        scan.status = ScanStatus.running
        db.commit()

        try:
            checks = [
                check_headers,
                check_tls,
                check_cors,
                check_open_redirect,
                check_subdomain_recon,
            ]
            with ThreadPoolExecutor(max_workers=len(checks)) as executor:
                module_results = [
                    _as_module_result(result)
                    for result in executor.map(lambda check: check(scan.target_url), checks)
                ]

            if scan.jwt_token:
                module_results.append(_as_module_result(check_jwt(scan.jwt_token)))
            else:
                module_results.append(_skipped_jwt_result())

            report = ScanReport(
                modules=module_results,
                overall_grade=_overall_grade(module_results),
            )
            scan.status = ScanStatus.completed
            scan.completed_at = datetime.utcnow()
            scan.results = report.model_dump()
            db.commit()
        except Exception as exc:
            logger.exception("Scan %s failed", scan_id)
            scan.status = ScanStatus.failed
            scan.results = {"error": str(exc)}
            db.commit()
    except Exception:
        # A database failure cannot safely be persisted, but must not be re-raised
        # because this task is intentionally terminal from Celery's perspective.
        logger.exception("Unable to update scan %s", scan_id)
    finally:
        db.close()
