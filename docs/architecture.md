# Architecture

## Service boundaries

- `milter-service` handles SMTP-time callbacks, assembles message context, and asks `policy-api` for a synchronous verdict.
- `policy-api` owns configuration, tenant-aware rules, provider settings, message trace, dashboards, and internal scan job lifecycle.
- `worker-scan` consumes Redis jobs for deep file scans, threat intel refreshes, and AI enrichment that should not block SMTP transactions.
- `web-ui` is a standalone admin console that talks only to the HTTP API.

## Decision flow

1. The MTA sends a message through the milter socket.
2. `milter-service` buffers envelope, headers, and body sections.
3. `policy-api` runs a fast-path verdict:
   - tenant and domain policy lookup
   - basic header and body heuristics
   - RBL/DNSBL checks
   - synchronous ClamAV scan for supported attachments
   - optional AI scoring in observe-only mode
4. The API returns `accept`, `reject`, `tempfail`, or `quarantine`.
5. Heavy or deferred checks are queued into Redis for `worker-scan`.
6. The message trace and aggregated metrics are updated in PostgreSQL.

## Data domains

- `organizations`, `domains`: multi-tenant-ready ownership model.
- `providers`: AV, RBL, anti-phishing, and AI integrations.
- `policies`: thresholds and resulting actions.
- `message_events`, `verdicts`, `scan_jobs`: operational data and traceability.
- `audit_events`: configuration changes and security-relevant operator actions.

## Provider model

Every external source is implemented behind a narrow adapter contract:

- antivirus adapters return file-level results
- threat-intel adapters return signal hits and metadata
- AI adapters return structured scores and explanations

This keeps the policy engine independent from vendor-specific request and response formats.
