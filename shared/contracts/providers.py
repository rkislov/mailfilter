from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


ProviderKind = Literal["av", "rbl", "anti_phishing", "ai", "auth"]
ProviderStatus = Literal["enabled", "disabled", "degraded"]


class ProviderConfig(BaseModel):
    name: str
    kind: ProviderKind
    enabled: bool = True
    base_url: str | None = None
    api_key: str | None = None
    settings: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


class ProviderSignal(BaseModel):
    provider_name: str
    kind: ProviderKind
    matched: bool
    summary: str
    score: float = 0.0
    metadata: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


class AIAnalysisResult(BaseModel):
    provider_name: str
    model: str
    score: float
    verdict_hint: Literal["spam", "suspicious", "ham", "unknown"] = "unknown"
    explanation: str
    observed_at: datetime = Field(default_factory=datetime.utcnow)


class AntivirusResult(BaseModel):
    provider_name: str
    filename: str
    status: ProviderStatus = "enabled"
    malicious: bool = False
    signature: str | None = None
    elapsed_ms: int | None = None
    details: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


class ClamAVMirrorSettings(BaseModel):
    database_mirror: str = "database.clamav.net"
    private_mirror: str | None = None
    script_updated: bool = True
    checks: int = 24
    compress_local_database: bool = False
    dns_database_info: str | None = None
    notify_clamd: bool = True


class AIProviderMode(BaseModel):
    value: Literal["disabled", "ollama", "gpustack"] = "disabled"


class AIRuntimeSettings(BaseModel):
    provider_mode: Literal["disabled", "ollama", "gpustack"] = "disabled"
    ollama_base_url: str = "http://ollama:11434/v1"
    ollama_model: str = "llama3.1"
    gpustack_base_url: str = "http://gpustack:8080/v1"
    gpustack_api_key: str | None = None
    gpustack_model: str = "llama3.1"
