# Another Called application (port 38081)

A downstream sample service. It accepts only application credentials: `X-Application-Id` plus
`X-Secret-Key`. These are validated by `AppCredentialsAuthenticationProvider`, a new provider
built per inbound-security.md §5.6:

- `supports()` inspects both headers and claims the request when either one is present.
  `authenticate()` requires both, so a request carrying only one header gets a 401 on every path,
  including `/health`.
- The application ID is looked up, and the secret is verified as
  `HMAC-SHA256(pepper, application_id + NUL + secret)` with `hmac.compare_digest`. The hash is
  bound to the ID, so copying one application's hash onto another does not work.
- Unknown IDs are compared against a dummy hash, which blocks timing-based enumeration.
- On success the provider returns a `SecurityPrincipal(authentication_type="APP_CREDENTIALS")`
  with the authorities configured for that application.

## Endpoints

| Method | Path | Required authority | Notes |
|---|---|---|---|
| GET | `/health` | none (public) | Invalid or partial credentials are still rejected with 401 |
| GET | `/api/v1/inventory` | `INVENTORY_READ` | Router-level `Depends(require_authority("INVENTORY_READ"))` |
| GET | `/api/v1/inventory/{sku}` | `INVENTORY_READ` | `sku` must match `^[A-Za-z0-9_-]{1,64}$`; unknown sku returns 404 |

401 responses carry `WWW-Authenticate: AppCredentials` and a generic detail. A missing authority
returns 403.

## Environment variables (names only)

| Variable | Required | Meaning |
|---|---|---|
| `SECURITY_INBOUND_APP_CREDENTIALS_PEPPER` | yes | Server-side HMAC pepper, at least 32 bytes |
| `SECURITY_INBOUND_APP_CREDENTIALS` | yes | JSON list of `{application_id, secret_hash, subject, authorities, roles?, tenant_id?, enabled?}`; `secret_hash` = 64-hex HMAC |
| `SECURITY_INBOUND_APPLICATION_ID_HEADER` | no | Default `X-Application-Id` |
| `SECURITY_INBOUND_SECRET_KEY_HEADER` | no | Default `X-Secret-Key` |
| `SECURITY_INBOUND_PUBLIC_PATHS` | no | Default `["/health", "/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"]`; only these exact paths are allowed |

The app refuses to start when the pepper or credential list is missing or invalid, the pepper is
too short, or application IDs are duplicated.

## Start, stop, restart

Prerequisites: `uv sync` in this folder, and `python3 ../scripts/generate_credentials.py` once
from the project root.

```bash
./app.sh start      # background; waits for GET /health
./app.sh status     # running/stopped, pid, health
./app.sh logs       # last 30 lines of ../.run/another-called-app.log
./app.sh restart
./app.sh stop
```

`app.sh` delegates to `../manage.sh`; use `../manage.sh start` to start all three apps.

## Run in the foreground and test

```bash
uv sync
set -a && . ./.env && set +a
uv run uvicorn --factory main:create_app --host 127.0.0.1 --port 38081

uv run pytest -q
uv run ruff check --select E,F,W,B,UP,S,ASYNC --ignore S101,E501 .
uv run mypy .
```

## Example curl

```bash
set -a && . ../mycaller-app/.env && set +a     # the caller's outbound credentials for this service
curl -s -H "X-Application-Id: $OUTBOUND_ANOTHER_CALLED_APP__APPLICATION_ID" \
        -H "X-Secret-Key: $OUTBOUND_ANOTHER_CALLED_APP__SECRET_KEY" \
        http://127.0.0.1:38081/api/v1/inventory                                                   # 200
curl -s -H "X-Application-Id: $OUTBOUND_ANOTHER_CALLED_APP__APPLICATION_ID" http://127.0.0.1:38081/health   # 401 (partial)
curl -s -H "X-API-Key: $OUTBOUND_CALLED_APP__API_KEY" http://127.0.0.1:38081/api/v1/inventory     # 401 (not accepted here)
```

> **Keep secrets out of `ps`.** `-H "X-Secret-Key: $VAR"` exposes the secret in curl's argv,
> which `ps` shows to anyone. Prefer a file only you can read:
>
> ```bash
> (umask 077; printf 'X-Application-Id: %s\nX-Secret-Key: %s\n' \
>    "$OUTBOUND_ANOTHER_CALLED_APP__APPLICATION_ID" "$OUTBOUND_ANOTHER_CALLED_APP__SECRET_KEY" > .hdr)
> curl -s -H @.hdr http://127.0.0.1:38081/api/v1/inventory
> ```


## Layout

`main.py` (factory), `api/routes/inventory.py`, `services/inventory_repository.py`, and `security/`.
That package holds the reference inbound modules plus the new
`security/inbound/app_credentials_provider.py`. Settings are in `security/configuration.py`.
