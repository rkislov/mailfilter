from __future__ import annotations

import base64
import re
import socket
import time
from urllib.parse import urlparse

import clamd
import dkim
import dns.resolver

from app.config import settings
from shared.clients.ai_client import OpenAICompatibleClient
from shared.contracts.message import AttachmentPayload
from shared.contracts.providers import AIAnalysisResult, AIRuntimeSettings, AntivirusResult, ProviderSignal


SPAM_KEYWORDS = {
    "lottery": 35,
    "crypto": 20,
    "urgent payment": 25,
    "gift card": 25,
    "wire transfer": 25,
    "verify account": 15,
    "password reset": 10,
}


class ClamAVAdapter:
    name = "clamav"

    def scan(self, attachment: AttachmentPayload) -> AntivirusResult:
        started = time.monotonic()
        try:
            client = clamd.ClamdNetworkSocket(host=settings.clamav_host, port=settings.clamav_port)
            result = client.instream(base64.b64decode(attachment.content_base64))
            status, signature = result.get("stream", ("UNKNOWN", None))
            return AntivirusResult(
                provider_name=self.name,
                filename=attachment.filename,
                malicious=status == "FOUND",
                signature=signature,
                elapsed_ms=int((time.monotonic() - started) * 1000),
                details={"status": status or "UNKNOWN"},
            )
        except Exception as exc:
            return AntivirusResult(
                provider_name=self.name,
                filename=attachment.filename,
                status="degraded",
                elapsed_ms=int((time.monotonic() - started) * 1000),
                details={"error": str(exc)},
            )


class DrWebAdapter:
    name = "drweb"

    def scan(self, attachment: AttachmentPayload) -> AntivirusResult:
        return AntivirusResult(
            provider_name=self.name,
            filename=attachment.filename,
            status="disabled",
            details={"note": "Adapter scaffolded. Configure vendor API credentials and transport."},
        )


class KasperskyAdapter:
    name = "kaspersky"

    def scan(self, attachment: AttachmentPayload) -> AntivirusResult:
        return AntivirusResult(
            provider_name=self.name,
            filename=attachment.filename,
            status="disabled",
            details={"note": "Adapter scaffolded. Configure Scan Engine endpoint and credentials."},
        )


class ThreatIntelAdapter:
    def check_rbl(self, client_ip: str | None, zones: list[str]) -> list[ProviderSignal]:
        if not client_ip:
            return []
        reversed_ip = ".".join(reversed(client_ip.split(".")))
        signals: list[ProviderSignal] = []
        for zone in zones:
            lookup = f"{reversed_ip}.{zone}"
            try:
                answers = dns.resolver.resolve(lookup, "A")
                for answer in answers:
                    signals.append(
                        ProviderSignal(
                            provider_name=zone,
                            kind="rbl",
                            matched=True,
                            summary=f"RBL hit for {client_ip}",
                            score=35,
                            metadata={"response": answer.to_text()},
                        )
                    )
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, socket.gaierror):
                continue
            except Exception as exc:
                signals.append(
                    ProviderSignal(
                        provider_name=zone,
                        kind="rbl",
                        matched=False,
                        summary=f"Lookup error for {client_ip}",
                        metadata={"error": str(exc)},
                    )
                )
        return signals

    def check_phishing_feeds(self, urls: list[str], blocked_domains: list[str]) -> list[ProviderSignal]:
        blocked = {item.lower() for item in blocked_domains}
        signals: list[ProviderSignal] = []
        for raw_url in urls:
            hostname = urlparse(raw_url).hostname or ""
            if hostname.lower() in blocked:
                signals.append(
                    ProviderSignal(
                        provider_name="anti-phishing-feed",
                        kind="anti_phishing",
                        matched=True,
                        summary=f"Blocked phishing domain matched: {hostname}",
                        score=45,
                        metadata={"url": raw_url},
                    )
                )
        return signals


class DKIMAdapter:
    name = "dkim"

    def verify(self, raw_message_base64: str | None, headers: dict[str, str]) -> ProviderSignal:
        signature = headers.get("DKIM-Signature")
        if not signature:
            return ProviderSignal(
                provider_name=self.name,
                kind="auth",
                matched=False,
                summary="No DKIM signature present",
                metadata={"status": "none"},
            )
        if not raw_message_base64:
            return ProviderSignal(
                provider_name=self.name,
                kind="auth",
                matched=False,
                summary="DKIM signature present but raw message is unavailable",
                metadata={"status": "unverified"},
            )
        domain = _extract_dkim_domain(signature)
        try:
            verified = dkim.verify(base64.b64decode(raw_message_base64))
            return ProviderSignal(
                provider_name=self.name,
                kind="auth",
                matched=not verified,
                summary="DKIM verification passed" if verified else "DKIM verification failed",
                score=20 if not verified else 0,
                metadata={"status": "pass" if verified else "fail", "domain": domain},
            )
        except Exception as exc:
            return ProviderSignal(
                provider_name=self.name,
                kind="auth",
                matched=False,
                summary="DKIM verification error",
                metadata={"status": "error", "domain": domain, "error": str(exc)},
            )


class AIGateway:
    def __init__(self, runtime: AIRuntimeSettings) -> None:
        self.runtime = runtime
        self.provider_name = runtime.provider_mode
        if runtime.provider_mode == "gpustack":
            base_url = runtime.gpustack_base_url
            api_key = runtime.gpustack_api_key or ""
            self.model = runtime.gpustack_model
        else:
            base_url = runtime.ollama_base_url
            api_key = "ollama"
            self.model = runtime.ollama_model
        self.client = OpenAICompatibleClient(
            base_url=base_url,
            api_key=api_key,
        )

    async def score_message(self, subject: str | None, body_text: str) -> AIAnalysisResult | None:
        if self.runtime.provider_mode == "disabled":
            return None
        prompt = (
            "Classify the email as spam, suspicious, ham, or unknown. "
            "Return a concise explanation and one integer score from 0 to 100."
        )
        try:
            response = await self.client.chat_completion(
                model=self.model,
                messages=[
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": f"Subject: {subject or ''}\n\nBody:\n{body_text[:4000]}"},
                ],
            )
            content = response["choices"][0]["message"]["content"]
            return AIAnalysisResult(
                provider_name=self.provider_name,
                model=self.model,
                score=_extract_score(content),
                verdict_hint=_extract_hint(content),
                explanation=content[:1000],
            )
        except Exception as exc:
            return AIAnalysisResult(
                provider_name=self.provider_name,
                model=self.model,
                score=0,
                verdict_hint="unknown",
                explanation=f"AI analysis unavailable: {exc}",
            )


def keyword_signals(subject: str | None, body_text: str) -> list[ProviderSignal]:
    haystack = f"{subject or ''}\n{body_text}".lower()
    signals: list[ProviderSignal] = []
    for keyword, score in SPAM_KEYWORDS.items():
        if keyword in haystack:
            signals.append(
                ProviderSignal(
                    provider_name="keyword-rules",
                    kind="anti_phishing",
                    matched=True,
                    summary=f"Keyword matched: {keyword}",
                    score=score,
                    metadata={"keyword": keyword},
                )
            )
    return signals


def _extract_score(content: str) -> float:
    for token in content.replace("\n", " ").split():
        candidate = token.strip(".,:;%")
        if candidate.isdigit():
            value = float(candidate)
            if 0 <= value <= 100:
                return value
    return 0.0


def _extract_hint(content: str) -> str:
    lowered = content.lower()
    if "spam" in lowered:
        return "spam"
    if "suspicious" in lowered:
        return "suspicious"
    if "ham" in lowered:
        return "ham"
    return "unknown"


def _extract_dkim_domain(signature: str) -> str | None:
    match = re.search(r"\bd=([^; ]+)", signature)
    if match:
        return match.group(1)
    return None
