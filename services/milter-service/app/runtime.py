from __future__ import annotations

import asyncio
import base64
import logging
import threading
from email.parser import BytesParser
from email.policy import default

import httpx

from app.config import settings

try:
    import Milter
except Exception:  # pragma: no cover - optional at runtime
    Milter = None

BaseMilter = Milter.Base if Milter is not None else object
LOG = logging.getLogger("anispam.milter")


class RuntimeState:
    def __init__(self) -> None:
        self.import_ok = Milter is not None
        self.running = False
        self.last_error: str | None = None


runtime_state = RuntimeState()


class PolicyClient:
    async def evaluate(self, payload: dict) -> dict:
        timeout = settings.smtp_decision_timeout_ms / 1000.0
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(settings.milter_policy_url, json=payload)
            response.raise_for_status()
            return response.json()


class AniSpamMilter(BaseMilter):  # type: ignore[misc]
    def __init__(self) -> None:
        self.client_ip = None
        self.helo_name = None
        self.mail_from = ""
        self.rcpt_to: list[str] = []
        self.headers: dict[str, str] = {}
        self.header_lines: list[bytes] = []
        self.body_chunks: list[bytes] = []
        self.queue_id = None
        self.policy_client = PolicyClient()

    def connect(self, hostname, family, hostaddr):
        self.client_ip = hostaddr[0] if isinstance(hostaddr, tuple) and hostaddr else None
        return Milter.CONTINUE

    def hello(self, hostname):
        self.helo_name = hostname
        return Milter.CONTINUE

    def envfrom(self, mailfrom, *args):
        self.mail_from = mailfrom
        return Milter.CONTINUE

    def envrcpt(self, to, *args):
        self.rcpt_to.append(to)
        return Milter.CONTINUE

    def header(self, name, value):
        self.headers[name] = value
        self.header_lines.append(f"{name}: {value}\r\n".encode("utf-8", errors="ignore"))
        return Milter.CONTINUE

    def body(self, chunk):
        self.body_chunks.append(chunk)
        return Milter.CONTINUE

    def eom(self):
        try:
            decision = asyncio.run(self.policy_client.evaluate(self._payload()))
            action = decision.get("action", "accept")
            for key, value in decision.get("headers_to_add", {}).items():
                self.addheader(key, value)
            if action == "reject":
                return Milter.REJECT
            if action == "tempfail":
                return Milter.TEMPFAIL
            if action == "quarantine":
                self.addheader("X-AniSpam-Quarantine", "true")
                return Milter.ACCEPT
            return Milter.ACCEPT
        except Exception:
            self.addheader("X-AniSpam-Error", "policy-unavailable")
            return Milter.TEMPFAIL

    def _payload(self) -> dict:
        raw_body = b"".join(self.body_chunks)
        raw_message = b"".join(self.header_lines) + b"\r\n" + raw_body
        message = BytesParser(policy=default).parsebytes(raw_message) if raw_message else None
        attachments = []
        if message is not None:
            for part in message.iter_attachments():
                payload = part.get_payload(decode=True) or b""
                attachments.append(
                    {
                        "filename": part.get_filename() or "attachment.bin",
                        "content_type": part.get_content_type(),
                        "content_base64": base64.b64encode(payload).decode("ascii"),
                        "size_bytes": len(payload),
                    }
                )
        return {
            "organization_slug": "default",
            "source": "milter",
            "queue_id": self.queue_id,
            "client_ip": self.client_ip,
            "helo": self.helo_name,
            "mail_from": self.mail_from,
            "rcpt_to": self.rcpt_to,
            "subject": self.headers.get("Subject"),
            "headers": self.headers,
            "body_text": raw_body.decode("utf-8", errors="ignore"),
            "raw_message_base64": base64.b64encode(raw_message).decode("ascii"),
            "attachments": attachments,
            "urls": [],
        }


def start_milter_server() -> None:
    if Milter is None:
        runtime_state.last_error = "pymilter import failed"
        LOG.error("pymilter import failed; milter listener is not available")
        return
    try:
        LOG.info("starting milter listener on %s", settings.milter_socket)
        runtime_state.running = True
        runtime_state.last_error = None
        Milter.factory = AniSpamMilter
        Milter.set_flags(Milter.ADDHDRS)
        Milter.runmilter("anispam-milter", settings.milter_socket, settings.milter_timeout_seconds)
    except Exception as exc:
        runtime_state.last_error = str(exc)
        LOG.exception("milter listener crashed")
        raise
    finally:
        runtime_state.running = False
