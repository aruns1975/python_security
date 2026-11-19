# Python security samples: inbound and outbound service security

Three self-contained FastAPI applications built on the `python-security-developer` reference
framework (`.claude/skills/python-security-developer/`). The framework follows the Spring Security
model: pure-ASGI authentication middleware, a `ContextVar`-backed `SecurityContextHolder`,
composable policies, `require_authority(...)` dependencies, `@pre_authorize` service methods, and a
`SecureHttpClient` that picks exactly one outbound auth strategy per registered service.

| App | Port | Role | README |
|---|---|---|---|
| MyCaller application | 58081 | Caller: protects its own API with client API keys and calls the other two apps | [mycaller-app/README.md](mycaller-app/README.md) |
| Called application | 48081 | Downstream service secured with an **API key** | [called-app/README.md](called-app/README.md) |
| Another Called application | 38081 | Downstream service secured with an **application ID + secret key** | [another-called-app/README.md](another-called-app/README.md) |

## Quick start

Prerequisites: Python 3.12+, [uv](https://docs.astral.sh/uv/), `curl` and `lsof` (macOS/Linux).

```bash
# 1. Install dependencies for each app (creates <app>/.venv)
for app in called-app another-called-app mycaller-app; do (cd $app && uv sync); done

# 2. Generate local credentials (writes the .env files; mode 0600, gitignored)
python3 scripts/generate_credentials.py

# 3. Start all three apps in the background and check them
./manage.sh start
./manage.sh status

# 4. Call the caller (see "Keep secrets out of ps" below for a safer form)
source .client-credentials.env
curl -s -H "X-API-Key: $MYCALLER_DASHBOARD_KEY" http://127.0.0.1:58081/api/v1/dashboard

# 5. Stop everything
./manage.sh stop
```

## Managing the applications

`manage.sh` runs the apps in the background, with a PID file and log per app in `.run/`.

```text
./manage.sh {start|stop|restart|status|logs} [all|mycaller-app|called-app|another-called-app]
```

| Command | What it does |
|---|---|
| `./manage.sh start` | Starts called-app, then another-called-app, then mycaller-app, and waits until each answers `GET /health` |
| `./manage.sh stop` | Stops mycaller-app first, then the downstream apps (SIGTERM, then SIGKILL after 10 s) |
| `./manage.sh restart` | Stops everything, then starts it again in dependency order |
| `./manage.sh status` | Shows running/stopped, port, PID, and whether `/health` responds |
| `./manage.sh logs` | Shows the last 30 log lines of each app (`LINES=100 ./manage.sh logs` for more) |
| `./manage.sh restart called-app` | Any command can target a single app |

Each app folder also has an `app.sh` wrapper for that app alone, for example
`called-app/app.sh restart` or `mycaller-app/app.sh status`.

Behaviour details:
- `start` is idempotent: an app that is already running is left alone. It refuses to start an
  app whose `.env` is missing or whose port is held by another process, and prints the end of
  the log if the app exits during startup (for example because of bad configuration).
- Each app's `.env` is exported into that app's process only, so secrets never cross apps and
  never appear on a command line.
- Stale PID files (left by a crash or `kill -9`) are detected and cleaned up automatically.
- Timeouts can be tuned with `START_TIMEOUT` (default 20 s) and `STOP_TIMEOUT` (default 10 s).
- After rotating credentials with `scripts/generate_credentials.py --force`, run
  `./manage.sh restart` so all three apps pick up the new values together.

`./run_all.sh` is the foreground alternative: it starts all three and stops them together on Ctrl-C.

## Architecture

```text
                         X-API-Key: <client key>
   client (curl) ──────────────────────────────────┐
                                                   ▼
                              ┌──────────────────────────────────────────┐
                              │  mycaller-app            :58081          │
                              │  inbound : API key (own client keys)     │
                              │  routes  : require_authority(...)        │
                              │  services: @pre_authorize(...)           │
                              │  outbound: SecureHttpClient              │
                              │    CALLED_APP         -> API_KEY         │
                              │    ANOTHER_CALLED_APP -> APP_CREDENTIALS │
                              └───────────┬────────────────┬─────────────┘
            X-API-Key: <outbound key>     │                │   X-Application-Id: <app id>
            (ApiKeyInterceptor)           │                │   X-Secret-Key: <secret>
                                          ▼                ▼   (AppCredentialsInterceptor)
             ┌──────────────────────────────┐    ┌──────────────────────────────────────┐
             │ called-app          :48081   │    │ another-called-app          :38081   │
             │ inbound: API key only        │    │ inbound: app ID + secret key only    │
             │ ApiKeyAuthenticationProvider │    │ AppCredentialsAuthenticationProvider │
             │ GET /api/v1/orders[/{id}]    │    │ GET /api/v1/inventory[/{sku}]        │
             │   ORDER_READ                 │    │   INVENTORY_READ                     │
             └──────────────────────────────┘    └──────────────────────────────────────┘
```

| App | Port | Accepts | Authorities granted to the caller |
|---|---|---|---|
| `mycaller-app/` | 58081 | `X-API-Key` (client keys) | `dashboard-client`: ORDER_READ, INVENTORY_READ, DASHBOARD_READ; `orders-client`: ORDER_READ |
| `called-app/` | 48081 | `X-API-Key` only | `mycaller-app`: ORDER_READ |
| `another-called-app/` | 38081 | `X-Application-Id` + `X-Secret-Key` only | `mycaller-app-<hex>`: INVENTORY_READ |

Public paths in each app (no credentials needed): `/health` and the interactive API docs:
`/docs` (Swagger UI), `/redoc`, `/openapi.json` and `/docs/oauth2-redirect`. They match exactly, so
nothing under them opens up. Every API endpoint requires authentication, including calls made from
Swagger's "Try it out": click **Authorize** and enter the credentials first.

## Call flows

**`GET /api/v1/orders` on mycaller**
1. `SecurityMiddleware` authenticates the client's `X-API-Key` (peppered HMAC lookup) and binds a
   `SecurityPrincipal` in the `ContextVar`. If authentication fails, the middleware returns its own 401.
2. Route dependency `require_authority("ORDER_READ")` authorizes the request (otherwise 403).
3. `OrderService.list_orders` (`@pre_authorize(has_authority("ORDER_READ"))`) calls `CalledAppClient`.
4. `SecureHttpClient` resolves `CALLED_APP` from the registry and validates the relative path.
   It builds a fresh request, so the inbound client key is never forwarded. `ApiKeyInterceptor`
   then adds `X-API-Key` from the secret store. The client re-checks the origin, sends with
   `follow_redirects=False`, and raises `OutboundServiceError` on any non-2xx response.
5. The response is validated with Pydantic. Any downstream failure becomes
   `502 {"error":"bad_gateway","detail":"Upstream service error"}`.

**`GET /api/v1/inventory` on mycaller:** the same flow with `INVENTORY_READ` and
`AnotherCalledAppClient`. `AppCredentialsInterceptor` adds `X-Application-Id` and `X-Secret-Key`.

**`GET /api/v1/dashboard` on mycaller:** the route requires DASHBOARD_READ, ORDER_READ and
INVENTORY_READ. `DashboardService.get_dashboard` (`@pre_authorize` DASHBOARD_READ) runs both
service calls concurrently with `asyncio.gather`. Each task inherits a copy of the security
context, so the nested `@pre_authorize` checks still apply. Each downstream receives only its own
credentials.

## Generate credentials, run, test

```bash
# 1. Credentials: writes called-app/.env, another-called-app/.env, mycaller-app/.env and
#    .client-credentials.env (mode 0600, gitignored). Prints names and paths only, never values.
python3 scripts/generate_credentials.py            # --force to rotate everything

# 2. Run all three in the background (logs: .run/<app>.log); stop with ./manage.sh stop
./manage.sh start

# 3. Call it
source .client-credentials.env
curl -s -H "X-API-Key: $MYCALLER_DASHBOARD_KEY" http://127.0.0.1:58081/api/v1/dashboard   # 200
curl -s -i http://127.0.0.1:58081/api/v1/dashboard                                          # 401
curl -s -H "X-API-Key: $MYCALLER_ORDERS_KEY"    http://127.0.0.1:58081/api/v1/dashboard   # 403

# 4. Tests, lint and type checks, per app
for app in called-app another-called-app mycaller-app; do
  (cd $app && uv sync && uv run pytest -q \
     && uv run ruff check --select E,F,W,B,UP,S,ASYNC --ignore S101,E501 . \
     && uv run mypy .)
done
```

> **Keep secrets out of `ps`.** `curl -H "X-API-Key: $VAR"` puts the expanded secret in curl's
> argv, so any local user can read it with `ps`. Outside a throwaway local demo, write the header
> to a file that only you can read, using the shell builtin `printf` so the value never appears in
> argv, and pass it with `-H @file`:
>
> ```bash
> (umask 077; printf 'X-API-Key: %s\n' "$MYCALLER_DASHBOARD_KEY" > .hdr-client)
> curl -s -H @.hdr-client http://127.0.0.1:58081/api/v1/dashboard
> ```


To run a single app in the foreground (for example with a debugger), export its `.env` into that
process only:
`cd called-app && set -a && . ./.env && set +a && uv run uvicorn --factory main:create_app --host 127.0.0.1 --port 48081`.

## Project layout

```text
python_security/
├── README.md                    this file
├── manage.sh                    start / stop / restart / status / logs
├── run_all.sh                   foreground run of all three apps (Ctrl-C stops)
├── scripts/generate_credentials.py
├── .client-credentials.env      generated client keys for calling mycaller-app (gitignored)
├── .run/                        PID files and logs (gitignored)
├── mycaller-app/                :58081, see mycaller-app/README.md
├── called-app/                  :48081, see called-app/README.md
├── another-called-app/          :38081, see another-called-app/README.md
├── security_ocumentation.md     the original architecture document
└── .claude/
    ├── skills/python-security-developer/   skill, reference docs, tested templates
    └── agents/python-security-agent.md     agent that applies the skill
```

Each app folder contains `main.py`, `api/`, `services/`, `security/` (its own copy of the
framework), `tests/`, `pyproject.toml`, `.env.example`, `app.sh` and its README. mycaller-app also
has `clients/`.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `missing <app>/.env` | Run `python3 scripts/generate_credentials.py` |
| `port NNNNN is already in use by another process` | Something else holds the port: `lsof -nP -iTCP:NNNNN -sTCP:LISTEN`, then stop it |
| `failed to start` followed by log lines | Usually invalid or missing configuration (the apps fail closed); read the log lines, then regenerate credentials |
| mycaller returns 502 | A downstream app is down: `./manage.sh status`, then `./manage.sh start` |
| 401 after rotating credentials | The apps still hold old values: `./manage.sh restart` |
| `status` says `not responding` | The process is alive but `/health` doesn't answer; check `./manage.sh logs <app>` |

## Extending security

| To... | Guide |
|---|---|
| Accept another inbound mechanism in called-app (for example JWT next to the API key) | [called-app/docs/adding-an-authentication-provider.md](called-app/docs/adding-an-authentication-provider.md) |
| Add an outbound auth type, a general interceptor or a new downstream service in mycaller-app | [mycaller-app/docs/adding-an-outbound-interceptor.md](mycaller-app/docs/adding-an-outbound-interceptor.md) |

The same steps apply to another-called-app (inbound) and to any other app built on this framework.
The next section shows both guides already applied once: the application ID + secret key scheme.

## How the app-credentials scheme extends the framework

Only extension points were used. No middleware, manager or client logic was rewritten.

| Side | Extension | Where |
|---|---|---|
| Inbound | `AppCredentialsAuthenticationProvider` (inbound-security.md §5.6), `name = "APP_CREDENTIALS"`, challenge `AppCredentials` | `another-called-app/security/inbound/app_credentials_provider.py` |
| Inbound | `AppCredentialEntry` settings model plus `build_providers` | `another-called-app/security/configuration.py` |
| Outbound | `AuthType.APP_CREDENTIALS`, plus `ServiceConfig.application_id_header` / `secret_key_header` | `mycaller-app/security/outbound/service_registry.py` |
| Outbound | `AppCredentialsInterceptor` (secret-store keys `application_id`, `secret_key`), registered in `outbound_security()` | `mycaller-app/security/outbound/interceptors/app_credentials.py`, `security/configuration.py` |
| Outbound | `X-Application-Id` and `X-Secret-Key` added to the headers `SecureHttpClient` reserves | `ServiceConfig.credential_headers`, `secure_http_client.py::_check_headers` |

The provider works as follows:
- `supports()` inspects both headers and claims the request if either one is present.
  `authenticate()` then requires both, so a request carrying only one header gets a 401
  ("Invalid application credentials"). That applies on `/health` too, instead of the request
  silently falling through to anonymous.
- The secret is compared as `HMAC-SHA256(pepper, application_id + NUL + secret)` with
  `hmac.compare_digest`. Because the ID is bound into the MAC, a hash copied from app A's record
  onto app B's never verifies. Application IDs are restricted to `[A-Za-z0-9._-]{1,128}`.
- An unknown application ID is compared against a random dummy hash, so it takes the same code
  path as a known ID and response timing cannot be used to enumerate valid IDs.
- Values longer than 512 characters are rejected. Disabled applications are rejected.
- On success it returns a `SecurityPrincipal(authentication_type="APP_CREDENTIALS")` with the
  authorities configured for that application.

## Security notes

- **http is local-only.** `ServiceConfig` rejects `http://` base URLs unless
  `allow_insecure_http: true`. That flag appears only in the generated local `.env` and in
  `.env.example`, with a comment that production must use https. Credentials sent over plain http
  can be read by anyone on the network path. In production, point `SECURITY_OUTBOUND_SERVICES` at
  https URLs, drop the flag, and never use `verify=False`.
- **Fail closed.** Every pepper, key list and credential list is a required setting with no
  default. Peppers shorter than 32 bytes, hash fields that are not 64-hex HMAC digests, duplicate
  application IDs, missing outbound secrets, a missing or swapped `CALLED_APP`/`ANOTHER_CALLED_APP`
  auth type, auth types with no interceptor, duplicate API key hashes or ids, and any public path
  outside the allow-list (`/health` plus the docs paths; for example `/` or a prefix) all stop startup. `allow_insecure_http` is
  accepted only for loopback hosts (`localhost`, `127.0.0.0/8`, `::1`).
- **Shared outbound client.** The client is built with `trust_env=False`, so proxy environment
  variables and `.netrc` cannot reroute credentials or add new ones. Its cookie jar uses a
  reject-all policy, so a `Set-Cookie` from one downstream is never stored, never replayed to the
  other service (same host, different port), and never shared across callers. The policy is set
  on the client's own jar because httpx copies a jar passed in through `httpx.Cookies(...)` and
  loses its policy.
- **Secrets at rest.** The called apps store only peppered hashes. The raw values exist only in
  the caller's outbound secrets and the clients' `.client-credentials.env`. Everything is
  gitignored and written with mode 0600. In production, use a secrets manager, either through
  `SecretStore` or by injecting env vars on the platform.
- **Rotation.** Run `scripts/generate_credentials.py --force` and restart, which rotates every
  key, secret and pepper at once. For zero-downtime rotation in a real deployment:
  1. Add a second entry (new `key_id`/hash or new `application_id`/hash) to the called app's list.
  2. Deploy the called app.
  3. Switch the caller's `OUTBOUND_*` secret.
  4. Remove the old entry. Rotating a pepper invalidates every hash made with it, so re-issue all
     keys when you rotate a pepper.
- **Failure reason codes.** Authentication failures are logged with a non-secret `reason` extra
  field (`missing`, `invalid`, `ambiguous`, `partial_headers`). The reason is never returned to
  the client.
- **Never logged:** API keys, secret keys, application IDs on failed attempts, peppers, the
  `X-API-Key`/`X-Secret-Key`/`Authorization`/`Cookie` headers, outbound query strings, and
  downstream bodies. The apps log only the outcome of each authentication attempt, the subject,
  the denied policy, and the outbound service id, method, path and status. Client-facing errors
  are generic, and the 502 body omits the service id and downstream status.
- **API docs are public.** Anyone who can reach an app can read its endpoint list and schemas
  (but not call them). For an internet-facing production deployment, consider disabling the docs
  with `FastAPI(docs_url=None, redoc_url=None, openapi_url=None)` or keeping them on an internal
  network.
- **Not covered (open items for production):** **rate limiting and lockout** in front of API-key
  and app-credential authentication. This is an open risk: online guessing is bounded only by key
  entropy (256-bit generated values). Also not covered: tenant/ownership filtering (the sample data has no tenants),
  mTLS between services, and a correlation-id middleware. The `CorrelationIdInterceptor` is wired
  in but does nothing until `correlation_id_var` is set.
