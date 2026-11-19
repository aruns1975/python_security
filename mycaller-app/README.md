# MyCaller application (port 58081)

The caller. Its own endpoints are protected by API keys that its clients send in `X-API-Key`.
These are different keys from the one MyCaller uses toward called-app. MyCaller calls two
registered downstream services through the reference `SecureHttpClient`:

| Service id | Base URL (local) | Auth type | Interceptor | Secret-store keys (`credential_ref`) |
|---|---|---|---|---|
| `CALLED_APP` | `http://127.0.0.1:48081` | `API_KEY` | `ApiKeyInterceptor` | `api_key` (`called-app`) |
| `ANOTHER_CALLED_APP` | `http://127.0.0.1:38081` | `APP_CREDENTIALS` | `AppCredentialsInterceptor` (new) | `application_id`, `secret_key` (`another-called-app`) |

Each service is wrapped in a typed client (`clients/called_app_client.py`,
`clients/another_called_app_client.py`) over `ServiceClient`, and every response is validated with
Pydantic. Any `OutboundServiceError` (downstream non-2xx, 401, redirect, transport error, invalid
body) becomes `502 {"error":"bad_gateway","detail":"Upstream service error"}`, with no service id,
status or body in the response. A downstream 404 on a detail endpoint becomes 404.

Callers can never set `Authorization`, `Proxy-Authorization`, `Cookie`, `Host`, `X-API-Key`,
`X-Application-Id` or `X-Secret-Key` on an outbound request. Every request is built fresh, so the
inbound client key is never forwarded.

## Endpoints

Authorization is enforced twice: by route dependencies and by `@pre_authorize` on the service layer.

| Method | Path | Route dependency | Service method (`@pre_authorize`) | Downstream |
|---|---|---|---|---|
| GET | `/health` | public | n/a | n/a |
| GET | `/api/v1/orders` | `ORDER_READ` | `OrderService.list_orders`: `ORDER_READ` | called-app |
| GET | `/api/v1/orders/{order_id}` | `ORDER_READ` | `OrderService.get_order`: `ORDER_READ` | called-app |
| GET | `/api/v1/inventory` | `INVENTORY_READ` | `InventoryService.list_inventory`: `INVENTORY_READ` | another-called-app |
| GET | `/api/v1/inventory/{sku}` | `INVENTORY_READ` | `InventoryService.get_item`: `INVENTORY_READ` | another-called-app |
| GET | `/api/v1/dashboard` | `DASHBOARD_READ` + `ORDER_READ` + `INVENTORY_READ` | `DashboardService.get_dashboard`: `DASHBOARD_READ`, then nested order and inventory checks | both, concurrently via `asyncio.gather` |

Generated client keys: `dashboard-client` (all three authorities) and `orders-client`
(`ORDER_READ` only, so it gets 403 on inventory and dashboard).

## Environment variables (names only)

| Variable | Required | Meaning |
|---|---|---|
| `SECURITY_INBOUND_API_KEY_PEPPER` | yes | HMAC pepper for client keys, at least 32 bytes |
| `SECURITY_INBOUND_API_KEYS` | yes | JSON list of client key records (hashes only) |
| `SECURITY_OUTBOUND_SERVICES` | yes | JSON registry; must define `CALLED_APP` (`API_KEY`) and `ANOTHER_CALLED_APP` (`APP_CREDENTIALS`) |
| `OUTBOUND_CALLED_APP__API_KEY` | yes | Raw key for called-app |
| `OUTBOUND_ANOTHER_CALLED_APP__APPLICATION_ID` | yes | Application ID for another-called-app |
| `OUTBOUND_ANOTHER_CALLED_APP__SECRET_KEY` | yes | Secret key for another-called-app |
| `SECURITY_INBOUND_API_KEY_HEADER`, `SECURITY_INBOUND_PUBLIC_PATHS` | no | Defaults `X-API-Key`, `["/health", "/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"]` (only these exact paths are allowed) |

Startup fails in any of these cases:
- a required service is missing or has the wrong auth type;
- an outbound secret is missing (the error names the variable, never the value);
- a base URL uses http without `allow_insecure_http`;
- an auth type has no interceptor.

`allow_insecure_http: true` appears only in the local `.env` and `.env.example`, and is
accepted only for loopback hosts. The shared client uses `trust_env=False` and a reject-all
cookie policy. **Production must
use https.**

## Start, stop, restart

Prerequisites: `uv sync` in this folder, and `python3 ../scripts/generate_credentials.py` once
from the project root. MyCaller needs both downstream apps running, so the easiest option is
`../manage.sh start` (starts all three in dependency order). To manage only this app:

```bash
./app.sh start      # background; waits for GET /health
./app.sh status     # running/stopped, pid, health
./app.sh logs       # last 30 lines of ../.run/mycaller-app.log
./app.sh restart
./app.sh stop
```

`app.sh` delegates to `../manage.sh`; see the root README for details.

## Run in the foreground and test

```bash
uv sync
set -a && . ./.env && set +a
uv run uvicorn --factory main:create_app --host 127.0.0.1 --port 58081   # needs both downstream apps running

uv run pytest -q
uv run ruff check --select E,F,W,B,UP,S,ASYNC --ignore S101,E501 .
uv run mypy .
```

The tests use `httpx.MockTransport` to verify the following:
- each downstream receives exactly its own credential headers;
- neither downstream receives the other's credentials or the inbound client key;
- the caller cannot forge reserved headers;
- path escapes and redirects are blocked;
- failures become a clean 502;
- secrets never appear in logs.

## Example curl

```bash
source ../.client-credentials.env
curl -s -H "X-API-Key: $MYCALLER_DASHBOARD_KEY" http://127.0.0.1:58081/api/v1/dashboard          # 200, both downstreams
curl -s -H "X-API-Key: $MYCALLER_DASHBOARD_KEY" http://127.0.0.1:58081/api/v1/orders/ORD-1001    # 200
curl -s -H "X-API-Key: $MYCALLER_DASHBOARD_KEY" http://127.0.0.1:58081/api/v1/inventory/SKU-100  # 200
curl -s -H "X-API-Key: $MYCALLER_ORDERS_KEY"    http://127.0.0.1:58081/api/v1/dashboard          # 403
curl -s -i http://127.0.0.1:58081/api/v1/dashboard                                                # 401
```

> **Keep secrets out of `ps`.** `-H "X-API-Key: $VAR"` exposes the key in curl's argv, which
> `ps` shows to anyone. Prefer a file only you can read:
> `(umask 077; printf 'X-API-Key: %s\n' "$MYCALLER_DASHBOARD_KEY" > .hdr) && curl -s -H @.hdr http://127.0.0.1:58081/api/v1/dashboard`.


## Extending security

To call a downstream that authenticates in a new way, add a general (non-secret) interceptor, or
register another downstream service, follow
[docs/adding-an-outbound-interceptor.md](docs/adding-an-outbound-interceptor.md). It has the steps, tested
examples (a static bearer token and an `X-Caller-App` header) and the test matrix.

## Layout

- `main.py`: factory, lifespan-owned outbound stack, and the required-services check.
- `api/routes/`: the routes. `api/errors.py` holds the 502 mapping and `api/dependencies.py` the
  dependencies.
- `services/business.py`: the `@pre_authorize` service layer.
- `clients/`: typed clients and their Pydantic models.
- `security/`: the reference inbound (API key) and outbound packages, plus
  `AuthType.APP_CREDENTIALS` and `interceptors/app_credentials.py`.
