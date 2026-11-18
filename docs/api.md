# The HTTP gateway

The gateway is a thin layer over the orchestrator. It authenticates the
caller, checks the role and the tenant, and then calls the methods the
orchestrator already has. It keeps no second copy of the state: everything it
shows is derived from the audit log and from the state file of the run.

There is no database and no ORM behind it. The state of the engine is the
hash-chained audit log, the content-addressed artifacts, the vector store and
the repository graph.

## Starting it

```bash
python -m oracle_hcm keygen                    # the signing key of the host
python -m oracle_hcm create-admin --username admin --tenant default
python -m oracle_hcm serve                     # http://127.0.0.1:8000
```

`create-admin` reads the password from the terminal with `getpass`, twice.
The password is never taken from the command line, never echoed and never
logged; only its Argon2 hash reaches `data/users.json`, which is ignored by
git.

`serve` binds to `127.0.0.1` by default, so the gateway is only reachable
from the host itself. To reach it from the LAN, name the address of the host
explicitly:

```bash
python -m oracle_hcm serve --host 0.0.0.0 --port 8000
# or
ORACLE_HCM_API_HOST=0.0.0.0 python -m oracle_hcm serve
```

On a LAN the cookie has to be marked secure (`ORACLE_HCM_COOKIE_SECURE=1`),
and the gateway has to sit behind a reverse proxy that terminates TLS.

## The session

`POST /auth/login` returns a short-lived JWT in an httpOnly, SameSite=strict
cookie. The body holds the id, the role, the tenant and the CSRF token.
Every state-changing request has to send that token back in the
`X-CSRF-Token` header; a read never does. The token is compared in constant
time.

A login that fails too often locks the account for a while. An address that
tries too often is refused before the password is even checked.

## The endpoints

| Method | Path | Role | What it does |
| --- | --- | --- | --- |
| GET | `/health` | none | The gateway is up. |
| POST | `/auth/login` | none | Opens a session, sets the cookie, returns the CSRF token. |
| POST | `/auth/logout` | any | Closes the session of the caller. |
| POST | `/tasks` | any | Submits a requirement and starts the run in the background. |
| GET | `/tasks` | any | The tasks of the tenant of the caller. |
| GET | `/tasks/{id}` | any | One task; the stage is derived from its events. |
| GET | `/tasks/{id}/events` | any | The audit events of one task. |
| GET | `/tasks/{id}/artifact` | any | The signed manifest of one task and its verification status. |
| GET | `/events/stream` | any | The events of the tenant, as they happen (SSE). |
| GET | `/approvals/pending` | admin | The approvals that wait for a decision. |
| POST | `/approvals/{id}/decide` | admin | Records the decision on one approval. |
| GET | `/metrics` | any | The counters of the tenant of the caller. |

Every endpoint except `/health` and the login needs a session. Every endpoint
that shows a task, an approval or a counter is limited to the tenant of the
caller: another tenant gets a `404`, never a hint that the object exists.

### POST /tasks

```json
{ "request": "Add overtime calculation", "sop_id": "sop_lightweight" }
```

The run starts in the background, in a worker thread with its own event loop,
so a slow model call never blocks the gateway. The answer holds the id of the
task, the tenant, the status and the stage. The run keeps its state on disk,
so it stays resumable across a restart of the gateway.

### GET /events/stream

A `text/event-stream` of the audit events of the tenant of the caller. The
stream starts at the sequence number given in `?since=`, so a client that
reconnects misses nothing. A comment line (`: keep-alive`) is sent when no
event arrived for a while. The events of another tenant are never written to
the stream.

### POST /approvals/{id}/decide

```json
{ "decision": "approved", "comment": "looks right", "artifact_hash": "<64 hex>" }
```

The `artifact_hash` is the hash of the exact artifact that was shown, as it
stands now. The gateway recomputes the hash of the artifact before it records
the decision and refuses the request with a `409` when the two differ, so a
decision can never be taken on an artifact that changed in the meantime. The
decision records the id of the administrator, the decision, the comment and
the hash, in the audit log and in the access log. An approved approval resumes
the run.

### GET /metrics

The counters of the tenant: the pass rate, the attempts per task, the tokens
every model used today, the security findings by severity, the number of risk
signals and the state of the last rollout.

## The errors

Every error is a JSON body with the code of the error and a short message.
Nothing else: no stack trace, no path of the host, no secret.

```json
{ "error": "not_found", "message": "unknown task 'a1b2'" }
```

| Code | Status | When |
| --- | --- | --- |
| `unauthenticated` | 401 | No session, or the session is over. |
| `forbidden` | 403 | The role or the CSRF token does not allow the action. |
| `not_found` | 404 | The object does not exist, or belongs to another tenant. |
| `conflict` | 409 | The artifact changed since it was shown. |
| `payload_too_large` | 413 | The body is larger than the limit. |
| `account_locked` | 429 | Too many failed logins. `Retry-After` says for how long. |
| `rate_limited` | 429 | Too many attempts from the same address. |

## The logs

Two hash-chained JSONL files sit next to each other:

- `data/audit.jsonl` is the audit log of the engine. The gateway appends the
  submission of a task and the decision on an approval to it.
- `data/access.jsonl` is the access log of the gateway. It holds the logins,
  the failed logins, the logouts and the approvals, with the user, the
  tenant, the address of the client and the moment. Every entry carries the
  hash of the previous one, so an entry that is edited or removed breaks the
  chain that follows it.

An entry of the access log names the user and the correlation id of the
request, so it can be joined with the audit log, which carries the same
correlation id.

## The configuration

The gateway reads the environment. The keys are never written to the code and
never printed.

| Variable | Default | What it does |
| --- | --- | --- |
| `JWT_SECRET` | none | The key the sessions are signed with. Required. |
| `ORACLE_HCM_JWT_TTL_SECONDS` | 3600 | How long a session lasts. |
| `ORACLE_HCM_CORS_ORIGINS` | none | The origins the browser may call from, comma separated. |
| `ORACLE_HCM_MAX_REQUEST_BYTES` | 65536 | The largest body the gateway accepts. |
| `ORACLE_HCM_API_HOST` | 127.0.0.1 | The address the gateway binds to. |
| `ORACLE_HCM_API_PORT` | 8000 | The port the gateway listens on. |
| `ORACLE_HCM_COOKIE_SECURE` | 0 | Marks the cookie as secure (HTTPS only). |
| `ORACLE_HCM_LOGIN_MAX_ATTEMPTS` | 5 | The failed logins that lock an account. |
| `ORACLE_HCM_LOGIN_WINDOW_SECONDS` | 900 | The window the failures are counted in. |
| `ORACLE_HCM_LOGIN_LOCKOUT_SECONDS` | 900 | How long a locked account stays locked. |
| `ORACLE_HCM_LOGIN_MAX_ATTEMPTS_PER_IP` | 30 | The attempts one address may make. |
| `ORACLE_HCM_KEEP_ALIVE_SECONDS` | 15 | How long the stream waits before a keep-alive. |
| `ORACLE_HCM_SECURITY_REPAIR_ATTEMPTS` | 3 | The maximum bounded security-feedback repair attempts before blocking the run. |

## The security of the gateway

- The role is checked on every endpoint, and the tenant on every object.
- The bodies are validated by Pydantic, with a maximum length on every field.
- A body that announces a size above the limit is refused before it is read.
- CORS is only enabled for the origins that are configured.
- Every answer carries the security headers: `X-Content-Type-Options`,
  `X-Frame-Options`, `Referrer-Policy`, `Content-Security-Policy`,
  `Cache-Control`, `Permissions-Policy` and `Cross-Origin-Opener-Policy`.
- No answer ever holds a secret: no key, no password, no hash of a password.
- The password of a user is stored as an Argon2id hash, and a login that
  names an unknown user takes the same time as a login with a wrong password.
