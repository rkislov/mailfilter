from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import AuditEvent, Domain, ListEntry, MessageEvent, Organization, Policy, Provider, ScanJob, User, Verdict
from app.providers import AIGateway, ClamAVAdapter, DKIMAdapter, DrWebAdapter, KasperskyAdapter, ThreatIntelAdapter, keyword_signals
from shared.clients.redis_queue import RedisQueue
from shared.contracts.message import DashboardSummary, MessageEvaluationRequest, MessageEvaluationResponse, SignalRecord
from shared.contracts.providers import AIRuntimeSettings, ClamAVMirrorSettings


def seed_defaults(db: Session) -> None:
    organization = db.scalar(select(Organization).where(Organization.slug == "default"))
    if organization is None:
        organization = Organization(name="Default Organization", slug="default")
        db.add(organization)
        db.flush()
        db.add_all(
            [
                Domain(organization_id=organization.id, name="local.anispam"),
                Policy(
                    organization_id=organization.id,
                    name="Default policy",
                    spam_reject_threshold=80.0,
                    spam_quarantine_threshold=60.0,
                    enable_ai=True,
                    enable_rbl=True,
                    enable_antivirus=True,
                    enable_anti_phishing=True,
                ),
                Provider(
                    organization_id=organization.id,
                    name="clamav",
                    kind="av",
                    base_url=f"tcp://{settings.clamav_host}:{settings.clamav_port}",
                    settings_json=json.dumps({"mode": "instream"}),
                ),
                Provider(
                    organization_id=organization.id,
                    name="spamhaus-zen",
                    kind="rbl",
                    base_url="dnsbl://zen.spamhaus.org",
                    settings_json=json.dumps({"zone": "zen.spamhaus.org"}),
                ),
                Provider(
                    organization_id=organization.id,
                    name="anti-phishing-default",
                    kind="anti_phishing",
                    base_url="feed://local/anti-phishing-default",
                    settings_json=json.dumps({"blocked_domains": ["login-payments.example", "auth-wallet.example"]}),
                ),
                Provider(
                    organization_id=organization.id,
                    name="ollama",
                    kind="ai",
                    enabled=settings.ai_provider_mode == "ollama",
                    base_url=settings.ollama_base_url,
                    settings_json=json.dumps({"model": settings.ollama_model}),
                ),
                Provider(
                    organization_id=organization.id,
                    name="gpustack",
                    kind="ai",
                    enabled=settings.ai_provider_mode == "gpustack",
                    base_url=settings.gpustack_base_url,
                    api_key=settings.gpustack_api_key or None,
                    settings_json=json.dumps({"model": settings.gpustack_model}),
                ),
                User(
                    organization_id=organization.id,
                    email=settings.default_superadmin_email,
                    role="superadmin",
                    password_hash=hashlib.sha256(settings.default_superadmin_password.encode("utf-8")).hexdigest(),
                ),
                ListEntry(
                    organization_id=organization.id,
                    list_type="allow",
                    match_type="sender_domain",
                    value="trusted.local",
                    action="accept",
                    enabled=True,
                    comment="Example allowlist domain",
                ),
                ListEntry(
                    organization_id=organization.id,
                    list_type="block",
                    match_type="sender_domain",
                    value="blocked.local",
                    action="reject",
                    enabled=True,
                    comment="Example blocklist domain",
                ),
            ]
        )
        db.commit()
    ensure_ai_runtime_provider(db)
    ensure_default_provider_metadata(db)
    ensure_clamav_config(ClamAVMirrorSettings())


def ensure_clamav_config(settings_obj: ClamAVMirrorSettings) -> str:
    config_dir = Path(settings.clamav_config_dir)
    config_dir.mkdir(parents=True, exist_ok=True)
    path = config_dir / "freshclam.conf"
    lines = [
        f"DatabaseMirror {settings_obj.database_mirror}",
        f"Checks {settings_obj.checks}",
        f"ScriptedUpdates {'yes' if settings_obj.script_updated else 'no'}",
        f"CompressLocalDatabase {'yes' if settings_obj.compress_local_database else 'no'}",
        f"NotifyClamd {'yes' if settings_obj.notify_clamd else 'no'}",
    ]
    if settings_obj.private_mirror:
        lines.append(f"PrivateMirror {settings_obj.private_mirror}")
    if settings_obj.dns_database_info:
        lines.append(f"DNSDatabaseInfo {settings_obj.dns_database_info}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


def get_clamav_settings(db: Session) -> ClamAVMirrorSettings:
    provider = db.scalar(select(Provider).where(Provider.name == "clamav-updates"))
    if provider is None:
        return ClamAVMirrorSettings()
    return ClamAVMirrorSettings(**json.loads(provider.settings_json))


def ensure_ai_runtime_provider(db: Session) -> None:
    provider = db.scalar(select(Provider).where(Provider.name == "ai-runtime"))
    if provider is None:
        provider = Provider(
            name="ai-runtime",
            kind="ai",
            enabled=settings.ai_provider_mode != "disabled",
            settings_json=json.dumps(_default_ai_runtime().model_dump()),
        )
        db.add(provider)
        db.commit()


def ensure_default_provider_metadata(db: Session) -> None:
    changed = False
    providers = db.scalars(select(Provider)).all()
    for provider in providers:
        if provider.name == "clamav" and not provider.base_url:
            provider.base_url = f"tcp://{settings.clamav_host}:{settings.clamav_port}"
            changed = True
        elif provider.name == "spamhaus-zen" and not provider.base_url:
            provider.base_url = "dnsbl://zen.spamhaus.org"
            changed = True
        elif provider.name == "anti-phishing-default" and not provider.base_url:
            provider.base_url = "feed://local/anti-phishing-default"
            changed = True
    if changed:
        db.commit()


def get_ai_runtime_settings(db: Session) -> AIRuntimeSettings:
    provider = db.scalar(select(Provider).where(Provider.name == "ai-runtime"))
    if provider is None:
        payload = _default_ai_runtime()
        save_ai_runtime_settings(db, payload)
        return payload
    return AIRuntimeSettings(**json.loads(provider.settings_json))


def save_ai_runtime_settings(db: Session, payload: AIRuntimeSettings, user_email: str = "system@anispam.local") -> None:
    provider = db.scalar(select(Provider).where(Provider.name == "ai-runtime"))
    if provider is None:
        provider = Provider(name="ai-runtime", kind="ai", enabled=payload.provider_mode != "disabled")
        db.add(provider)
        db.flush()
    provider.enabled = payload.provider_mode != "disabled"
    provider.base_url = payload.gpustack_base_url if payload.provider_mode == "gpustack" else payload.ollama_base_url
    provider.api_key = payload.gpustack_api_key if payload.provider_mode == "gpustack" else None
    provider.settings_json = json.dumps(payload.model_dump())
    provider.updated_at = datetime.utcnow()
    db.add(
        AuditEvent(
            organization_id=provider.organization_id,
            user_email=user_email,
            action="update_ai_runtime",
            target_kind="provider",
            target_id=str(provider.id or "ai-runtime"),
            details_json=provider.settings_json,
        )
    )
    db.commit()


def save_clamav_settings(db: Session, payload: ClamAVMirrorSettings, user_email: str = "system@anispam.local") -> str:
    provider = db.scalar(select(Provider).where(Provider.name == "clamav-updates"))
    settings_json = json.dumps(payload.model_dump())
    if provider is None:
        provider = Provider(name="clamav-updates", kind="av", settings_json=settings_json, enabled=True)
        db.add(provider)
    else:
        provider.settings_json = settings_json
        provider.updated_at = datetime.utcnow()
    db.flush()
    db.add(
        AuditEvent(
            organization_id=provider.organization_id,
            user_email=user_email,
            action="update_clamav_mirrors",
            target_kind="provider",
            target_id=str(provider.id or "clamav-updates"),
            details_json=settings_json,
        )
    )
    path = ensure_clamav_config(payload)
    db.commit()
    return path


async def evaluate_message(db: Session, request: MessageEvaluationRequest) -> MessageEvaluationResponse:
    organization = db.scalar(select(Organization).where(Organization.slug == request.organization_slug))
    if organization is None:
        organization = db.scalar(select(Organization).where(Organization.slug == "default"))
    if organization is None:
        raise RuntimeError("Default organization is missing")

    policy = db.scalar(select(Policy).where(Policy.organization_id == organization.id).order_by(Policy.id.asc()))
    if policy is None:
        raise RuntimeError("Policy is missing for organization")

    message_event = MessageEvent(
        organization_id=organization.id,
        source=request.source,
        queue_id=request.queue_id,
        client_ip=request.client_ip,
        helo=request.helo,
        mail_from=request.mail_from,
        rcpt_to_json=json.dumps(request.rcpt_to),
        subject=request.subject,
        headers_json=json.dumps(request.headers),
        body_preview=request.body_text[:4000],
    )
    db.add(message_event)
    db.flush()

    reasons: list[str] = []
    signal_records: list[SignalRecord] = []
    score = 0.0
    degraded = False

    list_match = _match_list_entries(
        db=db,
        organization_id=organization.id,
        mail_from=request.mail_from,
        client_ip=request.client_ip,
        helo=request.helo,
        rcpt_to=request.rcpt_to,
        subject=request.subject,
    )
    if list_match is not None:
        signal_records.append(
            SignalRecord(
                provider="lists",
                category="policy",
                severity="high" if list_match.list_type == "block" else "info",
                summary=f"{'Black' if list_match.list_type == 'block' else 'White'}list matched: {list_match.value}",
                details={
                    "list_type": list_match.list_type,
                    "match_type": list_match.match_type,
                    "value": list_match.value,
                    "action": list_match.action,
                    "comment": list_match.comment,
                },
            )
        )
        reasons.append(
            f"{'Black' if list_match.list_type == 'block' else 'White'}list matched: {list_match.value}"
        )
        action = "accept" if list_match.list_type == "allow" else list_match.action
        message_event.spam_score = 0.0 if action == "accept" else 100.0
        message_event.final_action = action
        message_event.degraded = False
        headers_to_add = {
            "X-AniSpam-Score": f"{message_event.spam_score:.2f}",
            "X-AniSpam-Verdict": action,
            "X-AniSpam-List": f"{list_match.list_type}:{list_match.match_type}",
        }
        verdict = Verdict(
            message_event_id=message_event.id,
            policy_id=policy.id,
            action=action,
            score=message_event.spam_score,
            reasons_json=json.dumps(reasons),
            signals_json=json.dumps([item.model_dump(mode="json") for item in signal_records]),
            headers_json=json.dumps(headers_to_add),
        )
        db.add(verdict)
        db.commit()
        return MessageEvaluationResponse(
            action=action,  # type: ignore[arg-type]
            score=message_event.spam_score,
            reasons=reasons,
            signals=signal_records,
            headers_to_add=headers_to_add,
            message_event_id=message_event.id,
            verdict_id=verdict.id,
            queued_scan_job_id=None,
            degraded=False,
        )

    keyword_hits = keyword_signals(request.subject, request.body_text)
    for signal in keyword_hits:
        score += signal.score
        reasons.append(signal.summary)
        signal_records.append(_to_signal_record(signal))

    dkim_signal = DKIMAdapter().verify(request.raw_message_base64, request.headers)
    if dkim_signal.metadata.get("status") == "fail":
        score += dkim_signal.score
        reasons.append(dkim_signal.summary)
    signal_records.append(_to_signal_record(dkim_signal))

    threat_intel = ThreatIntelAdapter()
    if policy.enable_rbl:
        rbl_providers = db.scalars(select(Provider).where(Provider.kind == "rbl", Provider.enabled.is_(True))).all()
        zones = [_provider_settings(item).get("zone", item.base_url or "") for item in rbl_providers]
        zones = [zone for zone in zones if zone]
        for signal in threat_intel.check_rbl(request.client_ip, zones):
            if signal.matched:
                score += signal.score
                reasons.append(signal.summary)
            elif signal.metadata.get("error"):
                degraded = True
            signal_records.append(_to_signal_record(signal))

    if policy.enable_anti_phishing:
        feeds = db.scalars(select(Provider).where(Provider.kind == "anti_phishing", Provider.enabled.is_(True))).all()
        blocked_domains: list[str] = []
        for provider in feeds:
            blocked_domains.extend(_provider_settings(provider).get("blocked_domains", []))
        for signal in threat_intel.check_phishing_feeds(request.urls, blocked_domains):
            score += signal.score
            reasons.append(signal.summary)
            signal_records.append(_to_signal_record(signal))

    if policy.enable_antivirus and request.attachments:
        av_results = []
        for attachment in request.attachments:
            av_results.extend(
                [
                    ClamAVAdapter().scan(attachment),
                    DrWebAdapter().scan(attachment),
                    KasperskyAdapter().scan(attachment),
                ]
            )
        for result in av_results:
            if result.malicious:
                score = max(score, 100)
                reasons.append(f"Malware detected by {result.provider_name}: {result.signature or result.filename}")
            if result.status == "degraded":
                degraded = True
            signal_records.append(
                SignalRecord(
                    provider=result.provider_name,
                    category="av",
                    severity="critical" if result.malicious else ("medium" if result.status == "degraded" else "info"),
                    summary=f"{result.provider_name} scanned {result.filename}",
                    details=result.model_dump(),
                )
            )

    ai_runtime = get_ai_runtime_settings(db)
    if policy.enable_ai and ai_runtime.provider_mode != "disabled":
        ai_result = await AIGateway(ai_runtime).score_message(request.subject, request.body_text)
        if ai_result is not None:
            score += ai_result.score * 0.2
            reasons.append(f"AI hint: {ai_result.verdict_hint}")
            signal_records.append(
                SignalRecord(
                    provider=ai_result.provider_name,
                    category="ai",
                    severity="medium" if ai_result.score >= 50 else "info",
                    summary=ai_result.explanation,
                    details=ai_result.model_dump(mode="json"),
                )
            )

    action = "accept"
    headers_to_add = {
        "X-AniSpam-Score": f"{score:.2f}",
        "X-AniSpam-DKIM": str(dkim_signal.metadata.get("status", "unknown")),
    }
    if score >= policy.spam_reject_threshold:
        action = "reject"
        headers_to_add["X-AniSpam-Verdict"] = "reject"
    elif score >= policy.spam_quarantine_threshold:
        action = "quarantine"
        headers_to_add["X-AniSpam-Verdict"] = "quarantine"
    elif degraded:
        action = "tempfail"
        headers_to_add["X-AniSpam-Verdict"] = "degraded"
    else:
        headers_to_add["X-AniSpam-Verdict"] = "accept"

    message_event.spam_score = score
    message_event.final_action = action
    message_event.degraded = degraded

    verdict = Verdict(
        message_event_id=message_event.id,
        policy_id=policy.id,
        action=action,
        score=score,
        reasons_json=json.dumps(reasons),
        signals_json=json.dumps([item.model_dump(mode="json") for item in signal_records]),
        headers_json=json.dumps(headers_to_add),
    )
    db.add(verdict)
    db.flush()

    queue_job_id: int | None = None
    if request.attachments or request.urls:
        scan_job = ScanJob(
            message_event_id=message_event.id,
            job_type="deep_scan",
            status="queued",
            payload_json=json.dumps(request.model_dump(mode="json")),
        )
        db.add(scan_job)
        db.flush()
        RedisQueue(redis_client=_redis(db), queue_name=settings.scan_queue_name).push(
            {"scan_job_id": scan_job.id, "message_event_id": message_event.id, "organization_slug": request.organization_slug}
        )
        queue_job_id = scan_job.id

    db.commit()
    return MessageEvaluationResponse(
        action=action,  # type: ignore[arg-type]
        score=score,
        reasons=reasons,
        signals=signal_records,
        headers_to_add=headers_to_add,
        message_event_id=message_event.id,
        verdict_id=verdict.id,
        queued_scan_job_id=queue_job_id,
        degraded=degraded,
    )


def dashboard_summary(db: Session) -> DashboardSummary:
    total_messages = db.scalar(select(func.count(MessageEvent.id))) or 0
    accepted_messages = db.scalar(select(func.count(MessageEvent.id)).where(MessageEvent.final_action == "accept")) or 0
    blocked_messages = db.scalar(select(func.count(MessageEvent.id)).where(MessageEvent.final_action == "reject")) or 0
    quarantined_messages = db.scalar(select(func.count(MessageEvent.id)).where(MessageEvent.final_action == "quarantine")) or 0
    avg_score = db.scalar(select(func.avg(MessageEvent.spam_score))) or 0.0
    provider_failures = db.scalar(select(func.count(MessageEvent.id)).where(MessageEvent.degraded.is_(True))) or 0
    return DashboardSummary(
        total_messages=int(total_messages),
        accepted_messages=int(accepted_messages),
        blocked_messages=int(blocked_messages),
        quarantined_messages=int(quarantined_messages),
        avg_score=float(avg_score),
        provider_failures=int(provider_failures),
        updated_at=datetime.now(timezone.utc),
    )


def _provider_settings(provider: Provider) -> dict[str, Any]:
    try:
        return json.loads(provider.settings_json)
    except json.JSONDecodeError:
        return {}


def _to_signal_record(signal: Any) -> SignalRecord:
    if signal.kind == "auth":
        severity = "medium" if signal.metadata.get("status") == "fail" else "info"
    else:
        severity = "high" if signal.matched and signal.score >= 35 else "info"
    return SignalRecord(
        provider=signal.provider_name,
        category=signal.kind,
        severity=severity,
        summary=signal.summary,
        details=signal.metadata,
    )


def _redis(_: Session):
    from app.db import redis_client

    return redis_client


def _default_ai_runtime() -> AIRuntimeSettings:
    return AIRuntimeSettings(
        provider_mode=settings.ai_provider_mode if settings.ai_provider_mode in {"disabled", "ollama", "gpustack"} else "disabled",
        ollama_base_url=settings.ollama_base_url,
        ollama_model=settings.ollama_model,
        gpustack_base_url=settings.gpustack_base_url,
        gpustack_api_key=settings.gpustack_api_key or None,
        gpustack_model=settings.gpustack_model,
    )


def _match_list_entries(
    db: Session,
    organization_id: int,
    mail_from: str,
    client_ip: str | None,
    helo: str | None,
    rcpt_to: list[str],
    subject: str | None,
) -> ListEntry | None:
    entries = db.scalars(
        select(ListEntry)
        .where(ListEntry.organization_id == organization_id, ListEntry.enabled.is_(True))
        .order_by(ListEntry.list_type.asc(), ListEntry.id.asc())
    ).all()
    sender_domain = mail_from.split("@", 1)[1].lower() if "@" in mail_from else ""
    subject_lower = (subject or "").lower()
    for entry in entries:
        value = entry.value.lower()
        matched = False
        if entry.match_type == "sender":
            matched = mail_from.lower() == value
        elif entry.match_type == "sender_domain":
            matched = sender_domain == value
        elif entry.match_type == "client_ip":
            matched = (client_ip or "").lower() == value
        elif entry.match_type == "helo":
            matched = (helo or "").lower() == value
        elif entry.match_type == "recipient":
            matched = any(item.lower() == value for item in rcpt_to)
        elif entry.match_type == "subject_contains":
            matched = value in subject_lower
        if matched:
            return entry
    return None
