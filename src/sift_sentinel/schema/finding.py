"""
SIFT Sentinel - Pydantic schema models.
Finding, AuditEntry, ConfidenceLevel, TokenUsage, SSdtTrust.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel


class ConfidenceLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    SPECULATIVE = "SPECULATIVE"
    UNRESOLVED = "UNRESOLVED"


class SSdtTrust(str, Enum):
    FULL = "full"
    DEGRADED = "degraded"
    UNTRUSTED = "untrusted"


class TokenUsage(BaseModel):
    input_tokens: int
    output_tokens: int
    model: str


class Finding(BaseModel):
    finding_id: str
    artifact: str
    timestamp: Optional[str] = None
    source_tools: list[str]
    tool_call_ids: list[str]
    raw_excerpt: str
    confidence_level: ConfidenceLevel
    evidence_type: str
    alternative_explanations: list[str]
    model_outputs: dict
    consensus: Optional[str] = None
    self_verification_passed: bool
    deterministic_check: str
    self_corrected: bool
    original_draft: Optional[dict] = None  # Full prior finding dict preserved by self-correction
    correction_reason: Optional[str] = None
    refutation_note: Optional[str] = None


class AuditEntry(BaseModel):
    tool_call_id: str
    session_id: str
    type: str
    tool_name: str
    tool_input: dict
    evidence_path: str
    execution_time_ms: int
    record_count: int
    token_usage: TokenUsage
    timestamp_utc: str
    timestamp_end_utc: str
    result_status: str
    finding_ids_produced: list[str]
    reasoning_chain: str = ""
    files_accessed: list[str] = []
    raw_stdout: str = ""
    raw_stderr: str = ""
    system_prompt_version: str = ""
    forensic_notes: list[str] = []
    conversation_summary: Optional[str] = None
