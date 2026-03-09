from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from shared.contracts.message import DashboardSummary, MessageEvaluationRequest, MessageEvaluationResponse
from shared.contracts.providers import AIRuntimeSettings, ClamAVMirrorSettings


class HealthResponse(BaseModel):
    status: str


class OrganizationCreate(BaseModel):
    name: str
    slug: str


class OrganizationRead(OrganizationCreate):
    model_config = ConfigDict(from_attributes=True)

    id: int
    is_active: bool
    created_at: datetime


class DomainCreate(BaseModel):
    organization_id: int
    name: str


class DomainRead(DomainCreate):
    model_config = ConfigDict(from_attributes=True)

    id: int
    is_active: bool
    created_at: datetime


class ProviderCreate(BaseModel):
    organization_id: int | None = None
    name: str
    kind: str
    enabled: bool = True
    base_url: str | None = None
    api_key: str | None = None
    settings: dict[str, Any] = Field(default_factory=dict)


class ProviderRead(ProviderCreate):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: datetime


class PolicyCreate(BaseModel):
    organization_id: int
    name: str
    spam_reject_threshold: float = 80.0
    spam_quarantine_threshold: float = 60.0
    enable_ai: bool = True
    enable_rbl: bool = True
    enable_antivirus: bool = True
    enable_anti_phishing: bool = True


class PolicyRead(PolicyCreate):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: datetime


class ScanJobRead(BaseModel):
    id: int
    message_event_id: int
    job_type: str
    status: str
    payload: dict[str, Any]
    result: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class MessageEventRead(BaseModel):
    id: int
    organization_id: int
    source: str
    queue_id: str | None
    client_ip: str | None
    helo: str | None
    mail_from: str
    rcpt_to: list[str]
    subject: str | None
    headers: dict[str, str]
    body_preview: str
    spam_score: float
    final_action: str
    degraded: bool
    created_at: datetime


class VerdictRead(BaseModel):
    id: int
    message_event_id: int
    policy_id: int | None
    action: str
    score: float
    reasons: list[str]
    signals: list[dict[str, Any]]
    headers: dict[str, str]
    created_at: datetime


class MessageTrace(BaseModel):
    message_event: MessageEventRead
    verdicts: list[VerdictRead]
    scan_jobs: list[ScanJobRead]


class DashboardResponse(BaseModel):
    summary: DashboardSummary


class AuditEventRead(BaseModel):
    id: int
    organization_id: int | None
    user_email: str
    action: str
    target_kind: str
    target_id: str
    details: dict[str, Any]
    created_at: datetime


class SettingsBundle(BaseModel):
    organizations: list[OrganizationRead]
    domains: list[DomainRead]
    providers: list[ProviderRead]
    policies: list[PolicyRead]
    clamav_mirrors: ClamAVMirrorSettings
    ai_runtime: AIRuntimeSettings


class ClamAVMirrorSettingsResponse(BaseModel):
    settings: ClamAVMirrorSettings
    config_path: str


class ClamAVMirrorSettingsUpdate(BaseModel):
    database_mirror: str = "database.clamav.net"
    private_mirror: str | None = None
    script_updated: bool = True
    checks: int = 24
    compress_local_database: bool = False
    dns_database_info: str | None = None
    notify_clamd: bool = True


class AIRuntimeSettingsResponse(BaseModel):
    settings: AIRuntimeSettings


class AIRuntimeSettingsUpdate(BaseModel):
    provider_mode: str = "disabled"
    ollama_base_url: str = "http://ollama:11434/v1"
    ollama_model: str = "llama3.1"
    gpustack_base_url: str = "http://gpustack:8080/v1"
    gpustack_api_key: str | None = None
    gpustack_model: str = "llama3.1"


EvaluateRequest = MessageEvaluationRequest
EvaluateResponse = MessageEvaluationResponse
