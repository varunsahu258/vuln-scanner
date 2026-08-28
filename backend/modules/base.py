"""Shared models for vulnerability-scanner modules."""

from typing import List

from pydantic import BaseModel


class Finding(BaseModel):
    check_name: str
    severity: str  # "info" | "low" | "medium" | "high"
    passed: bool
    detail: str


class ModuleResult(BaseModel):
    module_name: str
    findings: List[Finding]
    score: str  # "A" | "B" | "C" | "D" | "F"
