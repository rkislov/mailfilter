from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


DecisionAction = Literal["accept", "reject", "tempfail", "quarantine"]
MessageSource = Literal["milter", "api", "worker"]


class AttachmentPayload(BaseModel):
    filename: str
    content_type: str = "application/octet-stream"
    content_base64: str
    size_bytes: int = 0


class MessageEvaluationRequest(BaseModel):
    organization_slug: str = "default"
    source: MessageSource = "milter"
    queue_id: str | None = None
    client_ip: str | None = None
    helo: str | None = None
    mail_from: str
    rcpt_to: list[str] = Field(default_factory=list)
    subject: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    body_text: str = ""
    raw_message_base64: str | None = None
    attachments: list[AttachmentPayload] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)


class SignalRecord(BaseModel):
    provider: str
    category: str
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    summary: str
    details: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


class MessageEvaluationResponse(BaseModel):
    action: DecisionAction
    score: float = 0.0
    reasons: list[str] = Field(default_factory=list)
    signals: list[SignalRecord] = Field(default_factory=list)
    headers_to_add: dict[str, str] = Field(default_factory=dict)
    message_event_id: int | None = None
    verdict_id: int | None = None
    queued_scan_job_id: int | None = None
    degraded: bool = False


class DashboardSummary(BaseModel):
    total_messages: int
    accepted_messages: int
    blocked_messages: int
    quarantined_messages: int
    avg_score: float
    provider_failures: int
    updated_at: datetime
