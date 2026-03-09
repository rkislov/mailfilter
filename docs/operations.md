# Operations

## Startup

```bash
cp .env.example .env
docker compose up --build
```

## Services

- API: `http://localhost:8080`
- API docs: `http://localhost:8080/docs`
- UI: `http://localhost:8081`
- Milter socket: `inet:9900@0.0.0.0`

## LAN and DNS

- Set `NETWORK_SUBNET` to a Docker subnet that does not overlap with your LAN, VPN, or hypervisor networks.
- Set `DNS_RESOLVER_1` and `DNS_RESOLVER_2` to recursive DNS servers reachable from the Docker host.
- Set `DNS_SEARCH_DOMAIN` if your mail environment uses an internal search suffix.
- DNS matters for:
  - DKIM TXT lookups
  - RBL and DNSBL queries
  - anti-phishing feed host resolution
  - ClamAV mirror resolution
- If internal DNS blocks external recursion, use a local resolver like `Unbound` and point the stack to it.

Example:

```env
NETWORK_SUBNET=172.30.0.0/24
DNS_RESOLVER_1=192.168.1.1
DNS_RESOLVER_2=1.1.1.1
DNS_SEARCH_DOMAIN=mail.local
```

## ClamAV updates

- The UI exposes ClamAV mirror settings at the `ClamAV Updates` section.
- The API exposes the same configuration at:
  - `GET /api/v1/providers/clamav/mirrors`
  - `PUT /api/v1/providers/clamav/mirrors`
- Saving the form regenerates a shared `freshclam.conf` in the compose volume mounted into the `clamav` container.
- For production, point `DatabaseMirror` or `PrivateMirror` at your approved update infrastructure.

## Production notes

- Replace development credentials in `.env`.
- Put `postgres`, `redis`, and `clamav` on persistent volumes.
- Run `ollama` under the `ai` compose profile only when needed.
- Place `milter-service` on the same trusted network segment as the MTA.
- Use a reverse proxy or ingress controller with TLS in front of `policy-api` and `web-ui`.
- Keep commercial AV credentials and AI tokens in a secrets manager, not plain env files.

## Health checks

- `policy-api`: `/healthz`
- `milter-service`: `/healthz` on port `9901`
- `worker-scan`: Redis connectivity and API reachability are logged at startup

## Postfix example

See `infra/examples/postfix/main.cf.snippet` for a sample milter configuration.
