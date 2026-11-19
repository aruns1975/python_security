# Python Security Review Checklist & Anti-Patterns

Run this checklist on every piece of generated or reviewed code before declaring it done.
Each item is pass/fail; report failures with file:line and the fix.

## A. Inbound authentication

- [ ] Authentication runs in the pure-ASGI `SecurityMiddleware`, not per-endpoint code.
- [ ] Middleware produces 401 itself (does not rely on `app.exception_handler`).
- [ ] `SecurityContextHolder.reset_context(token)` in `finally`.
- [ ] JWT: explicit `algorithms` allow-list, no `none`, no HS/RS mixing; `iss`, `aud`, `exp`, `iat`,
      `sub` required; small leeway (≤ 60 s); keys from https JWKS or pinned PEM.
- [ ] No `jwt.decode(..., options={"verify_signature": False})` outside tests.
- [ ] JWKS fetch not on the event loop (`asyncio.to_thread`) and cached.
- [ ] API keys stored as HMAC-SHA256 (peppered) hashes; compared with `hmac.compare_digest`.
- [ ] Passwords hashed with argon2id/scrypt/bcrypt; verify in a thread; dummy-hash for unknown users.
- [ ] Invalid credentials on public paths → 401 (no silent anonymous fallback).
- [ ] Multiple credential types on one request → rejected.
- [ ] Public paths are an explicit allow-list; everything else requires authentication.
- [ ] Brute-force protection / rate limiting on credential-based auth.
- [ ] Error messages generic ("Invalid or expired token"); failure class logged, not returned.

## B. Authorization

- [ ] Every non-public endpoint has an explicit `Depends(require(...))` (or router-level dependency).
- [ ] Service methods callable from multiple entry points use `@pre_authorize` / `@secured`.
- [ ] Authorities (permissions) preferred over role checks for fine-grained decisions.
- [ ] Tenant/owner filtering happens in the data query (no IDOR); `@post_authorize` only as defence in depth.
- [ ] 401 vs 403 correct: anonymous → 401, authenticated-but-denied → 403.
- [ ] No authorization based on client-supplied headers/body fields (e.g. `X-User-Role`, `is_admin`).
- [ ] Privileged operations (role changes, deletes) require an explicit authority and are audit-logged.

## C. Context propagation

- [ ] No module-level globals or `threading.local()` for identity.
- [ ] Raw `ThreadPoolExecutor` / `run_in_executor` wrap with `contextvars.copy_context().run`.
- [ ] Work that outlives the request uses `create_detached_task` or explicit ids, not the caller's identity.
- [ ] Consumers/jobs bind an explicit least-privilege service principal.

## D. Outbound

- [ ] All calls go through `ServiceClient` / `SecureHttpClient`; no ad-hoc `httpx.AsyncClient()` or `requests` in business code.
- [ ] One shared `httpx.AsyncClient` from the lifespan; explicit timeouts and pool limits.
- [ ] `follow_redirects=False` on the shared client and on every send.
- [ ] Shared client: `trust_env=False` and a reject-all cookie policy (no cross-service / cross-user cookie replay).
- [ ] `allow_insecure_http` only for loopback hosts.
- [ ] Base URLs https; no userinfo; token URLs https.
- [ ] Callers pass relative paths only; final origin re-validated after interceptors.
- [ ] Caller cannot set `Authorization` / `Cookie` / API-key headers.
- [ ] Exactly one authentication interceptor per service, selected by config `auth_type`.
- [ ] Secrets resolved through `SecretStore`; registry holds only references.
- [ ] OAuth2 tokens cached per service, refreshed early, single-flight under a lock, invalidated on 401.
- [ ] Retries: idempotent methods only (or with `Idempotency-Key`); backoff with jitter; 4xx not retried.
- [ ] Errors raised as `OutboundServiceError` without URL query, headers, or body.
- [ ] Downstream responses validated (Pydantic) before use.
- [ ] Never `verify=False`; mTLS via `ssl.SSLContext` when required.
- [ ] User-supplied URLs (webhooks, callbacks) are NOT routed through `SecureHttpClient`; they need a
      separate SSRF-guarded client (resolve DNS, block private/link-local/metadata IPs, no credentials).

## E. Secrets & logging

- [ ] No secrets in source, YAML, Dockerfiles, test fixtures committed with real values, or default settings.
- [ ] `SecretStr` for secret settings; never `print`/log settings objects with secrets.
- [ ] Logs never contain: `Authorization`, cookies, tokens, API keys, passwords, client secrets, full JWT claims, query strings of outbound calls.
- [ ] Security events logged with structured fields: auth success/failure, authz denied, outbound auth type, token refresh.

## F. Quality gates

- [ ] Type hints on all public functions; `mypy` clean.
- [ ] `ruff check --select E,F,W,B,UP,S,ASYNC` clean (bandit `S` rules catch hard-coded secrets, `verify=False`, etc.).
- [ ] Tests from `testing.md` §5 matrix present and passing.

## Anti-patterns → fixes

| Anti-pattern | Fix |
|---|---|
| `jwt.decode(token, key)` without `algorithms=` / `audience=` | pass explicit `algorithms`, `audience`, `issuer`, `options={"require": [...]}` |
| `if api_key == settings.API_KEY:` | hash + `hmac.compare_digest`; store hashes |
| `current_user = None` module global set by middleware | `ContextVar` via `SecurityContextHolder` |
| `BaseHTTPMiddleware` raising `HTTPException(401)` | pure ASGI middleware returning a 401 response |
| Auth checks copy-pasted in each route | `Depends(require(policy))` / `@pre_authorize` |
| `httpx.get(user_supplied_url, headers={"Authorization": ...})` | `ServiceClient` with registered origin; never attach credentials to arbitrary URLs |
| `async with httpx.AsyncClient() as c:` per call | shared client from lifespan |
| `response.raise_for_status()` then logging the exception | `OutboundServiceError` (status only) |
| `logger.info("calling %s with headers %s", url, headers)` | log service id, method, path, status only |
| Fetching a new OAuth2 token per request | `ClientCredentialsTokenProvider` cache + lock |
| Shared `httpx.AsyncClient` with default cookie jar | reject-all cookie policy on `client.cookies.jar` |
| `verify=False` "temporarily" | fix the CA bundle (`verify="/path/ca.pem"` or `ssl.SSLContext`) |
| Returning `str(exc)` from PyJWT to the client | generic message; log `type(exc).__name__` |
