---
name: python-security-developer
description: >
  Writes production-quality inbound and outbound security code for Python services (FastAPI / Starlette / ASGI, HTTPX).
  Inbound: authentication (JWT bearer, API key, HTTP Basic, custom providers), pure-ASGI SecurityMiddleware,
  ContextVar-backed SecurityContextHolder, authorization policies, @pre_authorize / @secured / @post_authorize
  decorators, FastAPI Depends guards, 401/403 handling. Outbound: SecureHttpClient over a shared httpx.AsyncClient,
  service registry, API-key / Basic / OAuth2 client-credentials interceptors, token caching and refresh, SSRF and
  redirect protection, safe retries. Spring-Security-style programming model. Use this skill ANY time a Python task
  involves authentication, authorization, roles/permissions, securing endpoints, JWT validation, API keys, calling
  another service with credentials, OAuth2 tokens, service-to-service auth, or reviewing Python security code.
  Triggers on: "secure this endpoint", "add authentication", "add JWT auth", "validate token", "add API key auth",
  "add RBAC", "add permissions", "pre_authorize", "call service with OAuth2", "add outbound auth", "add bearer token
  to requests", "client credentials", "secure http client", "security context", "review security".
---

# Python Security Developer

Implements inbound and outbound security for Python services using a tested reference framework modelled on
Spring Security. **Never improvise security primitives.** Every component you write must come from, or be a
faithful adaptation of, the reference implementation in this skill.

Skill root: the directory containing this file (`.claude/skills/python-security-developer/` in this project).

## Reference material (read before writing code)

| File | Read when |
|---|---|
| `references/inbound-security.md` | Any authentication, identity, authorization, decorator, dependency, middleware work |
| `references/outbound-security.md` | Any call from this service to another service with credentials |
| `references/configuration-and-wiring.md` | Adding the framework to an app, settings, lifespan, middleware order, consumers/jobs |
| `references/testing.md` | Always — every change ships with tests |
| `references/security-checklist.md` | Always — final gate before reporting done; also the rubric for reviews |
| `templates/` | Tested drop-in code: `security/` package, `tests/`, example `main.py`, pytest config |

Load only the references relevant to the task, but `testing.md` and `security-checklist.md` are always in scope.

## Workflow

### 1. Classify the request
- **Inbound** (who is calling / what may they do), **outbound** (how we authenticate to others), or **both**.
- **Greenfield** (no `security/` package in the repo) vs **extend** (package exists) vs **review** (no code changes).

### 2. Inspect the target repo
- Find the framework and versions (`pyproject.toml`, `requirements*.txt`): FastAPI/Starlette, httpx, PyJWT, Pydantic v1/v2, Python version. The reference targets Python ≥ 3.11, Pydantic v2, httpx ≥ 0.27.
- Search for existing security code: `grep -rn "jwt\.\|Authorization\|BaseHTTPMiddleware\|Depends(\|ContextVar\|httpx\.\|requests\." --include=*.py`.
- Note the repo's conventions (layout, naming, logging setup, settings style) — generated code must read like the surrounding code.
- If the repo already has a different but sound security design, extend it using the reference's *principles* rather than replacing it; say so explicitly. If it has unsafe patterns (see checklist anti-patterns), flag them.
- If library APIs differ from the reference (older PyJWT/httpx, Pydantic v1), check current docs (Context7) before adapting.

### 3. Implement
- **Greenfield**: copy the needed modules from `templates/security/` into the repo's package (keep the module names; omit unused providers/interceptors; fix import roots to match the repo). Copy `templates/tests/` alongside and adapt.
- **Extend**: follow the extension recipes:
  - New inbound mechanism → `inbound-security.md` §5.6.
  - Protect endpoints → `require(...)` / `require_authority(...)` dependencies (§7.4); router-level for whole areas.
  - Protect service methods → `@pre_authorize` / `@secured` / `@post_authorize` (§7.3).
  - Tenant / ownership → filter in the query (§7.5); never rely on RBAC alone.
  - New downstream service → add a `ServiceConfig` entry + secrets (`configuration-and-wiring.md` §2), expose a typed client wrapping `ServiceClient` (`outbound-security.md` §8).
  - New outbound auth type → new `AuthType` member + `AuthenticationInterceptor` subclass registered in `outbound_security()`.
- Wire it per `configuration-and-wiring.md`: lifespan-owned shared `httpx.AsyncClient`, `configure_inbound_security` before `CORSMiddleware`, explicit public paths, fail-closed settings.

### 4. Non-negotiable rules
1. Identity lives in a `ContextVar` via `SecurityContextHolder`; reset in `finally`. No globals, no `threading.local`.
2. Authentication in pure ASGI middleware that returns its own 401; never per-endpoint token parsing.
3. JWT: explicit algorithms, verify signature + `iss` + `aud` + `exp` + required claims; never `verify_signature=False` outside tests.
4. Secrets: API keys hashed (peppered HMAC) + `hmac.compare_digest`; passwords slow-hashed; outbound secrets via `SecretStore`; nothing secret in code, YAML, or defaults.
5. Outbound: only through `SecureHttpClient`/`ServiceClient`; relative paths; `follow_redirects=False`; https; caller cannot set credential headers; one auth strategy per service, chosen by config.
6. Never log tokens, keys, passwords, `Authorization`/`Cookie` headers, or outbound query strings.
7. Generic client-facing error messages; 401 for unauthenticated (with `WWW-Authenticate`), 403 for denied.
8. Fail closed: misconfiguration must stop startup, never disable security.

### 5. Test
Write or adapt tests per `testing.md` §5 matrix. Run them (`pytest -q`) plus `ruff check --select E,F,W,B,UP,S,ASYNC` and `mypy` if the repo uses them. Do not report success with failing or unrun tests — state exactly what ran.

### 6. Verify against the checklist
Walk `references/security-checklist.md` sections relevant to the change. Fix every failing item, or list it as an open risk with the reason.

### 7. Report
Summarise: what was added/changed (file links), which mechanisms are active, required environment variables and secrets (names only), test results, checklist outcome, and any deliberate deviations from the reference with justification.

## Review mode
When asked to review (not write) security code: do steps 1–2, then score the code against `security-checklist.md`, reporting each failure as `file:line — issue — fix (reference §)`, ordered by severity (credential exposure / auth bypass first). Do not modify files unless asked.

## Scope boundaries
- User-supplied URLs (webhooks, callbacks, URL fetchers) are **not** registered services: do not send them through `SecureHttpClient` with credentials. Build a separate SSRF-guarded client (DNS resolution + private/link-local/metadata IP blocking, no credentials, no redirects) and say why.
- Interactive user login (authorization code + PKCE, sessions, cookies/CSRF) is outside the reference; apply the same principles, use a maintained library (e.g. Authlib), and label the code as not covered by the reference.
- Django/Flask: reuse the provider, principal, ContextVar holder, policies, decorators and the entire outbound package unchanged; replace only the middleware and dependency layer with the framework's equivalents (Django middleware, Flask `before_request`), keeping reset-in-finally semantics.
