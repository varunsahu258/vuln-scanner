"""API-facing models for scan records and reports."""

from typing import List

from pydantic import BaseModel


class Finding(BaseModel):
    check_name: str
    severity: str
    passed: bool
    detail: str


class ModuleResult(BaseModel):
    module_name: str
    findings: List[Finding]
    score: str


class ScanReport(BaseModel):
    modules: List[ModuleResult]
    overall_grade: str


class ScanRequest(BaseModel):
    target_url: str
    jwt_token: str | None = None
    authorized: bool
