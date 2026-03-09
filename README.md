# AniSpam

AniSpam is a containerized anti-spam platform for SMTP-time filtering through the `milter` protocol. The repository is organized as a multi-service Python platform with a separate admin UI, policy engine, async worker, and pluggable provider adapters for AV, threat intelligence, and AI scoring.

## Services

- `services/milter-service`: libmilter-compatible ingress that talks to the policy API.
- `services/policy-api`: configuration, verdict engine, logs, dashboards, and internal orchestration API.
- `services/worker-scan`: async queue worker for deep scans and AI enrichment.
- `services/web-ui`: TailwindCSS-based admin UI served as a standalone container.
- `postgres`, `redis`, `clamav`: infrastructure services.

## Quick start

1. Copy `.env.example` to `.env`.
2. Start the stack:

```bash
docker compose up --build
```

3. Open the admin UI at [http://localhost:8081](http://localhost:8081).
4. Open the API docs at [http://localhost:8080/docs](http://localhost:8080/docs).

## Postfix relay setup

AniSpam is designed to sit next to a Postfix relay and inspect mail through the `milter` protocol before the message is accepted for delivery. A common deployment pattern is:

1. Run the AniSpam stack with `docker compose up --build`.
2. Install Postfix on the relay host or run it in a separate trusted container.
3. Point Postfix at the AniSpam milter socket.
4. Configure the relay destination and restrict which clients are allowed to submit mail.

Example `main.cf` snippet:

```cf
myhostname = relay.example.local
myorigin = example.local
inet_interfaces = all
mynetworks = 127.0.0.0/8 10.0.0.0/8

relayhost = [smtp.upstream.example]:25

smtpd_recipient_restrictions = permit_mynetworks,reject_unauth_destination

smtpd_milters = inet:127.0.0.1:9900
non_smtpd_milters = inet:127.0.0.1:9900
milter_default_action = tempfail
milter_protocol = 6
```

If Postfix runs outside Docker and AniSpam runs in Docker, publish port `9900` from `milter-service` and use the Docker host IP instead of `127.0.0.1`. If both services are on the same Docker network, Postfix can use `inet:milter-service:9900`.

Minimal relay behavior:

- Incoming mail is accepted only from trusted hosts listed in `mynetworks`.
- Postfix forwards outbound mail to `relayhost`.
- AniSpam evaluates the message during SMTP and returns `accept`, `reject`, `tempfail`, or quarantine-style tagging headers.

The repository also includes a ready-made Postfix sample in `infra/examples/postfix/main.cf.snippet`.

## First iteration capabilities

- Tenant-aware configuration model for organizations and domains.
- SMTP-time policy evaluation endpoint for milter integration.
- ClamAV adapter plus stubs for Dr.Web and Kaspersky Scan Engine.
- ClamAV mirror configuration through API and web UI, with shared `freshclam.conf` generation.
- DNSBL/RBL and anti-phishing feed checks with caching hooks.
- AI scoring gateway for Ollama or GPUStack via OpenAI-compatible APIs.
- Decision logs, message trace, scan jobs, and dashboard summary endpoints.

## Repository layout

```text
.
├── docker-compose.yml
├── docs/
├── infra/examples/postfix/
├── services/
│   ├── milter-service/
│   ├── policy-api/
│   ├── web-ui/
│   └── worker-scan/
└── shared/
    ├── clients/
    └── contracts/
```

See `docs/architecture.md` and `docs/operations.md` for deployment details.
