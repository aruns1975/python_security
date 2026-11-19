# Called application (port 48081)

A downstream sample service. It accepts only API keys (`X-API-Key`), which are validated by the
reference `ApiKeyAuthenticationProvider`. Keys are stored as peppered HMAC-SHA256 hashes, never in
plain text, and compared with `hmac.compare_digest`. In the sample setup, its only client is
`mycaller-app`.

## Endpoints

| Method | Path | Required authority | Notes |
|---|---|---|---|
| GET | `/health` | none (public) | Invalid credentials are still rejected with 401 |
| GET | `/api/v1/orders` | `ORDER_READ` | `Depends(require_authority("ORDER_READ"))` |
| GET | `/api/v1/orders/{order_id}` | `ORDER_READ` | `order_id` must match `^[A-Za-z0-9_-]{1,64}$`; unknown id returns 404 |

The API docs (`/docs`, `/redoc`, `/openapi.json`) are public; use **Authorize** in Swagger UI to
call the endpoints. Responses: 401 with `WWW-Authenticate: ApiKey`
for a missing or invalid key, and 403 `{"error":"forbidden","detail":"Access denied"}` for a
missing authority.

## Environment variables (names only)

| Variable | Required | Meaning |
|---|---|---|
| `SECURITY_INBOUND_API_KEY_PEPPER` | yes | Server-side HMAC pepper, at least 32 bytes |
| `SECURITY_INBOUND_API_KEYS` | yes | JSON list of `{key_id, key_hash, subject, authorities, roles?, tenant_id?, enabled?}`; `key_hash` = 64-hex HMAC |
| `SECURITY_INBOUND_API_KEY_HEADER` | no | Default `X-API-Key` |
| `SECURITY_INBOUND_PUBLIC_PATHS` | no | Default `["/health", "/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"]`; only these exact paths are allowed |

The app refuses to start when the pepper or key list is missing or invalid. See `.env.example`;
real values come from `../scripts/generate_credentials.py`.

## Start, stop, restart

Prerequisites: `uv sync` in this folder, and `python3 ../scripts/generate_credentials.py` once
from the project root.

```bash
./app.sh start      # background; waits for GET /health
./app.sh status     # running/stopped, pid, health
./app.sh logs       # last 30 lines of ../.run/called-app.log
./app.sh restart
./app.sh stop
```

`app.sh` delegates to `../manage.sh`; use `../manage.sh start` to start all three apps.

## Run in the foreground and test

```bash
uv sync
set -a && . ./.env && set +a
uv run uvicorn --factory main:create_app --host 127.0.0.1 --port 48081

uv run pytest -q
uv run ruff check --select E,F,W,B,UP,S,ASYNC --ignore S101,E501 .
uv run mypy .
```

## Example curl

```bash
set -a && . ../mycaller-app/.env && set +a     # the caller's outbound key for this service
curl -s -H "X-API-Key: $OUTBOUND_CALLED_APP__API_KEY" http://127.0.0.1:48081/api/v1/orders            # 200
curl -s -H "X-API-Key: $OUTBOUND_CALLED_APP__API_KEY" http://127.0.0.1:48081/api/v1/orders/ORD-1002   # 200
curl -s -i http://127.0.0.1:48081/api/v1/orders                                                       # 401
curl -s -H "X-Application-Id: x" -H "X-Secret-Key: y" http://127.0.0.1:48081/api/v1/orders            # 401 (not accepted here)
curl -s http://127.0.0.1:48081/health                                                                 # 200
```

> **Keep secrets out of `ps`.** `-H "X-API-Key: $VAR"` exposes the key in curl's argv, which
> `ps` shows to anyone. Prefer a file only you can read:
> `(umask 077; printf 'X-API-Key: %s\n' "$OUTBOUND_CALLED_APP__API_KEY" > .hdr) && curl -s -H @.hdr http://127.0.0.1:48081/api/v1/orders`.


## Extending security

To accept another inbound mechanism (for example JWT bearer tokens) next to the API key, follow
[docs/adding-an-authentication-provider.md](docs/adding-an-authentication-provider.md). It has the steps for any provider,
a complete, tested JWT example, a skeleton for custom schemes and the test matrix.

## Layout

`main.py` (factory), `api/routes/orders.py`, `services/order_repository.py`, and `security/`, which
holds a copy of the reference inbound package containing only the API-key provider. Settings are in
`security/configuration.py`.
