from __future__ import annotations

import json
import re

from fastapi import Depends, FastAPI, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import Base, SessionLocal, engine, get_db, redis_client
from app.models import AuditEvent, Domain, ListEntry, MessageEvent, Organization, Policy, Provider, ScanJob, Verdict
from app.schemas import (
    AIRuntimeSettingsResponse,
    AIRuntimeSettingsUpdate,
    AuditEventRead,
    ClamAVMirrorSettingsResponse,
    ClamAVMirrorSettingsUpdate,
    DashboardResponse,
    DomainCreate,
    DomainRead,
    EvaluateRequest,
    EvaluateResponse,
    HealthResponse,
    ListEntryCreate,
    ListEntryRead,
    ListEntryUpdate,
    MessageEventRead,
    MessageTrace,
    OrganizationCreate,
    OrganizationRead,
    PolicyCreate,
    PolicyRead,
    ProviderCreate,
    ProviderRead,
    ProviderUpdate,
    ScanJobRead,
    SettingsBundle,
    VerdictRead,
)
from app.service import (
    dashboard_summary,
    evaluate_message,
    get_ai_runtime_settings,
    get_clamav_settings,
    save_ai_runtime_settings,
    save_clamav_settings,
    seed_defaults,
)
from shared.contracts.providers import AIRuntimeSettings, ClamAVMirrorSettings

app = FastAPI(title="AniSpam Policy API", version="0.1.0")


@app.on_event("startup")
def on_startup() -> None:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_defaults(db)


@app.get("/healthz", response_model=HealthResponse)
def healthcheck() -> HealthResponse:
    redis_client.ping()
    return HealthResponse(status="ok")


@app.post("/api/v1/milter/evaluate", response_model=EvaluateResponse)
async def milter_evaluate(payload: EvaluateRequest, db: Session = Depends(get_db)) -> EvaluateResponse:
    return await evaluate_message(db, payload)


@app.get("/api/v1/dashboard", response_model=DashboardResponse)
def get_dashboard(db: Session = Depends(get_db)) -> DashboardResponse:
    return DashboardResponse(summary=dashboard_summary(db))


@app.get("/api/v1/settings", response_model=SettingsBundle)
def get_settings(db: Session = Depends(get_db)) -> SettingsBundle:
    return SettingsBundle(
        organizations=[OrganizationRead.model_validate(item) for item in db.scalars(select(Organization)).all()],
        domains=[DomainRead.model_validate(item) for item in db.scalars(select(Domain)).all()],
        providers=[_provider_read(item) for item in db.scalars(select(Provider)).all()],
        policies=[PolicyRead.model_validate(item) for item in db.scalars(select(Policy)).all()],
        clamav_mirrors=get_clamav_settings(db),
        ai_runtime=get_ai_runtime_settings(db),
        list_entries=[_list_entry_read(item) for item in db.scalars(select(ListEntry).order_by(ListEntry.id.desc())).all()],
    )


@app.get("/api/v1/providers", response_model=list[ProviderRead])
def list_providers(kind: str | None = Query(default=None), db: Session = Depends(get_db)) -> list[ProviderRead]:
    query = select(Provider).order_by(Provider.kind.asc(), Provider.name.asc(), Provider.id.asc())
    if kind:
        query = query.where(Provider.kind == kind)
    return [_provider_read(item) for item in db.scalars(query).all()]


@app.post("/api/v1/organizations", response_model=OrganizationRead)
def create_organization(payload: OrganizationCreate, db: Session = Depends(get_db)) -> OrganizationRead:
    organization = Organization(name=payload.name, slug=payload.slug)
    db.add(organization)
    db.commit()
    db.refresh(organization)
    return OrganizationRead.model_validate(organization)


@app.post("/api/v1/domains", response_model=DomainRead)
def create_domain(payload: DomainCreate, db: Session = Depends(get_db)) -> DomainRead:
    domain = Domain(organization_id=payload.organization_id, name=payload.name)
    db.add(domain)
    db.commit()
    db.refresh(domain)
    return DomainRead.model_validate(domain)


@app.post("/api/v1/providers", response_model=ProviderRead)
def create_provider(payload: ProviderCreate, db: Session = Depends(get_db)) -> ProviderRead:
    normalized = _normalize_provider_payload(
        name=payload.name,
        kind=payload.kind,
        base_url=payload.base_url,
        settings=payload.settings,
    )
    provider = Provider(
        organization_id=payload.organization_id,
        name=normalized["name"],
        kind=normalized["kind"],
        enabled=payload.enabled,
        base_url=normalized["base_url"],
        api_key=payload.api_key,
        settings_json=json.dumps(normalized["settings"]),
    )
    db.add(provider)
    db.flush()
    db.add(
        AuditEvent(
            organization_id=provider.organization_id,
            user_email="admin@web-ui.local",
            action="create_provider",
            target_kind="provider",
            target_id=str(provider.id),
            details_json=json.dumps(_provider_read(provider).model_dump(mode="json")),
        )
    )
    db.commit()
    db.refresh(provider)
    return _provider_read(provider)


@app.patch("/api/v1/providers/{provider_id}", response_model=ProviderRead)
def update_provider(provider_id: int, payload: ProviderUpdate, db: Session = Depends(get_db)) -> ProviderRead:
    provider = db.get(Provider, provider_id)
    if provider is None:
        raise HTTPException(status_code=404, detail="Provider not found")

    current_settings = _safe_json(provider.settings_json, {})
    next_name = payload.name if payload.name is not None else provider.name
    next_kind = payload.kind if payload.kind is not None else provider.kind
    next_base_url = payload.base_url if payload.base_url is not None else provider.base_url
    next_settings = payload.settings if payload.settings is not None else current_settings
    normalized = _normalize_provider_payload(
        name=next_name,
        kind=next_kind,
        base_url=next_base_url,
        settings=next_settings,
    )

    if payload.organization_id is not None:
        provider.organization_id = payload.organization_id
    if payload.enabled is not None:
        provider.enabled = payload.enabled
    if payload.api_key is not None:
        provider.api_key = payload.api_key

    provider.name = normalized["name"]
    provider.kind = normalized["kind"]
    provider.base_url = normalized["base_url"]
    provider.settings_json = json.dumps(normalized["settings"])

    db.add(
        AuditEvent(
            organization_id=provider.organization_id,
            user_email="admin@web-ui.local",
            action="update_provider",
            target_kind="provider",
            target_id=str(provider.id),
            details_json=json.dumps(_provider_read(provider).model_dump(mode="json")),
        )
    )
    db.commit()
    db.refresh(provider)
    return _provider_read(provider)


@app.delete("/api/v1/providers/{provider_id}")
def delete_provider(provider_id: int, db: Session = Depends(get_db)) -> dict[str, bool]:
    provider = db.get(Provider, provider_id)
    if provider is None:
        raise HTTPException(status_code=404, detail="Provider not found")
    db.add(
        AuditEvent(
            organization_id=provider.organization_id,
            user_email="admin@web-ui.local",
            action="delete_provider",
            target_kind="provider",
            target_id=str(provider.id),
            details_json=json.dumps(
                {
                    "name": provider.name,
                    "kind": provider.kind,
                    "base_url": provider.base_url,
                    "settings": _safe_json(provider.settings_json, {}),
                }
            ),
        )
    )
    db.delete(provider)
    db.commit()
    return {"ok": True}


@app.post("/api/v1/policies", response_model=PolicyRead)
def create_policy(payload: PolicyCreate, db: Session = Depends(get_db)) -> PolicyRead:
    policy = Policy(**payload.model_dump())
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return PolicyRead.model_validate(policy)


@app.get("/api/v1/messages", response_model=list[MessageEventRead])
def list_messages(limit: int = Query(default=20, le=100), db: Session = Depends(get_db)) -> list[MessageEventRead]:
    messages = db.scalars(select(MessageEvent).order_by(MessageEvent.id.desc()).limit(limit)).all()
    return [_message_read(item) for item in messages]


@app.get("/api/v1/messages/{message_event_id}/trace", response_model=MessageTrace)
def get_message_trace(message_event_id: int, db: Session = Depends(get_db)) -> MessageTrace:
    message_event = db.get(MessageEvent, message_event_id)
    if message_event is None:
        raise HTTPException(status_code=404, detail="Message not found")
    verdicts = db.scalars(select(Verdict).where(Verdict.message_event_id == message_event_id).order_by(Verdict.id.asc())).all()
    jobs = db.scalars(select(ScanJob).where(ScanJob.message_event_id == message_event_id).order_by(ScanJob.id.asc())).all()
    return MessageTrace(
        message_event=_message_read(message_event),
        verdicts=[_verdict_read(item) for item in verdicts],
        scan_jobs=[_scan_job_read(item) for item in jobs],
    )


@app.get("/api/v1/audit", response_model=list[AuditEventRead])
def list_audit_events(limit: int = Query(default=50, le=200), db: Session = Depends(get_db)) -> list[AuditEventRead]:
    events = db.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(limit)).all()
    return [
        AuditEventRead(
            id=item.id,
            organization_id=item.organization_id,
            user_email=item.user_email,
            action=item.action,
            target_kind=item.target_kind,
            target_id=item.target_id,
            details=_safe_json(item.details_json, {}),
            created_at=item.created_at,
        )
        for item in events
    ]


@app.get("/api/v1/lists", response_model=list[ListEntryRead])
def list_list_entries(db: Session = Depends(get_db)) -> list[ListEntryRead]:
    entries = db.scalars(select(ListEntry).order_by(ListEntry.id.desc())).all()
    return [_list_entry_read(item) for item in entries]


@app.post("/api/v1/lists", response_model=ListEntryRead)
def create_list_entry(payload: ListEntryCreate, db: Session = Depends(get_db)) -> ListEntryRead:
    entry = ListEntry(**payload.model_dump())
    db.add(entry)
    db.flush()
    db.add(
        AuditEvent(
            organization_id=entry.organization_id,
            user_email="admin@web-ui.local",
            action="create_list_entry",
            target_kind="list_entry",
            target_id=str(entry.id),
            details_json=json.dumps(payload.model_dump()),
        )
    )
    db.commit()
    db.refresh(entry)
    return _list_entry_read(entry)


@app.patch("/api/v1/lists/{entry_id}", response_model=ListEntryRead)
def update_list_entry(entry_id: int, payload: ListEntryUpdate, db: Session = Depends(get_db)) -> ListEntryRead:
    entry = db.get(ListEntry, entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="List entry not found")
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(entry, key, value)
    db.add(
        AuditEvent(
            organization_id=entry.organization_id,
            user_email="admin@web-ui.local",
            action="update_list_entry",
            target_kind="list_entry",
            target_id=str(entry.id),
            details_json=json.dumps(payload.model_dump(exclude_unset=True)),
        )
    )
    db.commit()
    db.refresh(entry)
    return _list_entry_read(entry)


@app.delete("/api/v1/lists/{entry_id}")
def delete_list_entry(entry_id: int, db: Session = Depends(get_db)) -> dict[str, bool]:
    entry = db.get(ListEntry, entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="List entry not found")
    db.add(
        AuditEvent(
            organization_id=entry.organization_id,
            user_email="admin@web-ui.local",
            action="delete_list_entry",
            target_kind="list_entry",
            target_id=str(entry.id),
            details_json=json.dumps({"value": entry.value, "list_type": entry.list_type}),
        )
    )
    db.delete(entry)
    db.commit()
    return {"ok": True}


@app.get("/api/v1/providers/clamav/mirrors", response_model=ClamAVMirrorSettingsResponse)
def read_clamav_mirrors(db: Session = Depends(get_db)) -> ClamAVMirrorSettingsResponse:
    settings_payload = get_clamav_settings(db)
    config_path = save_clamav_settings(db, settings_payload)
    return ClamAVMirrorSettingsResponse(settings=settings_payload, config_path=config_path)


@app.put("/api/v1/providers/clamav/mirrors", response_model=ClamAVMirrorSettingsResponse)
def update_clamav_mirrors(payload: ClamAVMirrorSettingsUpdate, db: Session = Depends(get_db)) -> ClamAVMirrorSettingsResponse:
    settings_payload = ClamAVMirrorSettings(**payload.model_dump())
    config_path = save_clamav_settings(db, settings_payload, user_email="admin@web-ui.local")
    return ClamAVMirrorSettingsResponse(settings=settings_payload, config_path=config_path)


@app.get("/api/v1/providers/ai/runtime", response_model=AIRuntimeSettingsResponse)
def read_ai_runtime(db: Session = Depends(get_db)) -> AIRuntimeSettingsResponse:
    return AIRuntimeSettingsResponse(settings=get_ai_runtime_settings(db))


@app.put("/api/v1/providers/ai/runtime", response_model=AIRuntimeSettingsResponse)
def update_ai_runtime(payload: AIRuntimeSettingsUpdate, db: Session = Depends(get_db)) -> AIRuntimeSettingsResponse:
    settings_payload = AIRuntimeSettings(**payload.model_dump())
    save_ai_runtime_settings(db, settings_payload, user_email="admin@web-ui.local")
    return AIRuntimeSettingsResponse(settings=settings_payload)


def _provider_read(item: Provider) -> ProviderRead:
    return ProviderRead(
        id=item.id,
        organization_id=item.organization_id,
        name=item.name,
        kind=item.kind,
        enabled=item.enabled,
        base_url=item.base_url,
        api_key=item.api_key,
        settings=_safe_json(item.settings_json, {}),
        created_at=item.created_at,
        updated_at=item.updated_at,
    )


def _message_read(item: MessageEvent) -> MessageEventRead:
    return MessageEventRead(
        id=item.id,
        organization_id=item.organization_id,
        source=item.source,
        queue_id=item.queue_id,
        client_ip=item.client_ip,
        helo=item.helo,
        mail_from=item.mail_from,
        rcpt_to=_safe_json(item.rcpt_to_json, []),
        subject=item.subject,
        headers=_safe_json(item.headers_json, {}),
        body_preview=item.body_preview,
        spam_score=item.spam_score,
        final_action=item.final_action,
        degraded=item.degraded,
        created_at=item.created_at,
    )


def _verdict_read(item: Verdict) -> VerdictRead:
    return VerdictRead(
        id=item.id,
        message_event_id=item.message_event_id,
        policy_id=item.policy_id,
        action=item.action,
        score=item.score,
        reasons=_safe_json(item.reasons_json, []),
        signals=_safe_json(item.signals_json, []),
        headers=_safe_json(item.headers_json, {}),
        created_at=item.created_at,
    )


def _scan_job_read(item: ScanJob) -> ScanJobRead:
    return ScanJobRead(
        id=item.id,
        message_event_id=item.message_event_id,
        job_type=item.job_type,
        status=item.status,
        payload=_safe_json(item.payload_json, {}),
        result=_safe_json(item.result_json, {}),
        created_at=item.created_at,
        updated_at=item.updated_at,
    )


def _list_entry_read(item: ListEntry) -> ListEntryRead:
    return ListEntryRead(
        id=item.id,
        organization_id=item.organization_id,
        list_type=item.list_type,
        match_type=item.match_type,
        value=item.value,
        action=item.action,
        enabled=item.enabled,
        comment=item.comment,
        created_at=item.created_at,
        updated_at=item.updated_at,
    )


def _safe_json(raw: str, default):
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return default


def _normalize_provider_payload(name: str, kind: str, base_url: str | None, settings: dict) -> dict[str, object]:
    normalized_name = name.strip()
    normalized_kind = kind.strip()
    normalized_base_url = base_url.strip() if isinstance(base_url, str) and base_url.strip() else None
    normalized_settings = dict(settings or {})

    if normalized_kind == "rbl":
        zone = str(normalized_settings.get("zone") or "").strip().lower()
        if not zone and normalized_base_url and "://" in normalized_base_url:
            zone = normalized_base_url.split("://", 1)[1].strip().lower()
        if not zone:
            raise HTTPException(status_code=422, detail="RBL zone is required")
        normalized_settings["zone"] = zone
        normalized_base_url = f"dnsbl://{zone}"

    if normalized_kind == "anti_phishing":
        raw_domains = normalized_settings.get("blocked_domains", [])
        if isinstance(raw_domains, str):
            raw_domains = re.split(r"[\n,;]+", raw_domains)
        blocked_domains = []
        for item in raw_domains:
            candidate = str(item).strip().lower()
            if candidate and candidate not in blocked_domains:
                blocked_domains.append(candidate)
        if not blocked_domains:
            raise HTTPException(status_code=422, detail="At least one phishing domain is required")
        normalized_settings["blocked_domains"] = blocked_domains
        if not normalized_base_url:
            slug = re.sub(r"[^a-z0-9]+", "-", normalized_name.lower()).strip("-") or "provider"
            normalized_base_url = f"feed://local/{slug}"

    return {
        "name": normalized_name,
        "kind": normalized_kind,
        "base_url": normalized_base_url,
        "settings": normalized_settings,
    }
