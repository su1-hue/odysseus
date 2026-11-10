# Odysseus — Authentik SSO + Per-User Isolation

Notes document (STEP 1 of the SSO/isolation task). Written **before** any code
change. Repo: `/home/realmont/services/odysseus` (branch `dev`), service on
port **12353**, public URL `https://12353.vr2.in` (Cloudflare → cloudflared
tunnel → uvicorn). Authentik: `https://12390.vr2.in` (local 127.0.0.1:12390).

---

## 1. App architecture at a glance

- Python 3.12, FastAPI, SQLAlchemy + SQLite (`data/app.db`), single global
  engine/`SessionLocal` in `core/database.py`.
- `app.py` (1523 lines) — app factory, `AuthMiddleware`, static serving,
  `/login` route (serves `static/login.html`), auth-exempt route set.
- `core/auth.py` — `AuthManager`: user store (`data/auth.json`), session
  store (`data/sessions.json`), `create_session_trusted(username)` (the SSO
  hook), TOTP, admin/privilege helpers.
- `core/middleware.py` — `require_admin`, internal-tool token, security headers.
- `src/auth_helpers.py` — `get_current_user`, `effective_user`,
  `require_user`, `require_privilege`, `storage_owner_for_request`,
  `owner_filter(query, model_cls, user, include_shared=True)`.
- `src/constants.py` — every path under `DATA_DIR` (`data/`).
- `src/tool_execution.py` — per-turn agent workspace (`_active_workspace`
  contextvar, default `data/agent_workspace`); `src/containment.py` —
  process containment.
- `routes/*` — one module per feature; several top-level files are
  backward-compat shims re-exporting from subpackages (`routes/email/`,
  `routes/document/`, `routes/search/`, `routes/memory/`, …).
- `static/app.js` — SPA orchestrator; **lines 204–209 patch `fetch`: any 401
  (except `/api/auth/*`) does `window.location.href = '/login'`**. This is
  the SPA's auth redirect — it needs **no change** for SSO because `/login`
  will 302 to `/auth/login`.

## 2. Data inventory

### 2.1 SQLite `data/app.db` — 36 tables

**Tables WITH an `owner` column (username, lowercase; NULL = legacy/shared):**

| Table | Table | Table |
|---|---|---|
| api_tokens | email_calendar_invitations | provider_auth_sessions |
| background_tool_jobs | gallery_albums | scheduled_tasks |
| caldav_deleted_events | gallery_images | sessions |
| calendars | integrations | signatures |
| comparisons | memories | user_tools |
| crew_members | model_endpoints | editor_drafts |
| documents | notes | notification_logs |
| | | email_accounts |

(24 user-scoped tables; `api_tokens` = `ody_` bearer tokens, `owner` = the
admin who minted the token.)

**Tables WITHOUT `owner` (child/derived or global) and how they are scoped:**

| Table | Scoping mechanism |
|---|---|
| chat_messages | FK → `sessions.owner` (query via session id) |
| chat_messages_fts* (5 tables) | FTS side-tables of chat_messages |
| document_versions | FK → `documents.owner` |
| calendar_events | FK → `calendars.owner` |
| task_runs | FK → `scheduled_tasks.owner` |
| user_tool_data | FK → `user_tools.owner` |
| email_account_owner_locks | lock rows, derived from email_accounts |
| mcp_servers | global (admin-configured integrations) |
| webhooks | global (admin-configured) |

**Other DBs:** `data/scheduled_emails.db`, `data/email_cache.db`
(email feature; rows keyed by email account which is owner-scoped).

### 2.2 JSON stores under `data/`

| File | Contents | Owner scoping |
|---|---|---|
| `auth.json` | `users: {username: {password_hash, is_admin, privileges?, totp?...}}` | n/a (identity store) |
| `sessions.json` | `{token: {username, expiry}}` | per-user by token → username |
| `memory.json` | long-term memory items | per-user (owner field / user key) |
| `settings.json` | app settings | global + per-user prefs |
| `user_prefs.json` | per-user UI prefs | keyed by username |
| `features.json` | feature flags | global |
| `presets.json` | chat presets | per-user |
| `integrations.json` | integrations (also DB table) | per-user |
| `contacts.json` | contacts | per-user |
| `cookbook_state.json` | cookbook state | global (code) |
| `bg_jobs.json` | background job state | per-job owner |
| `containment_grants.json` | process containment grants | global |
| `vault.json` | secrets vault | global (admin) |
| `tidy_calendar_state.json` | calendar tidy state | per-user |
| `skills.json` | skill metadata | per-user |
| `embedding_endpoint.json` | embedding endpoint config | global (admin) |
| `uploads/uploads.json` | upload index `{file_id: {name, mime, owner, ...}}` | per-file `owner` |

### 2.3 File/directory stores under `data/`

| Path | Contents | Per-user? |
|---|---|---|
| `agent_workspace/` | agent file-tool workspace (shared default) | **NO → becomes per-user (see §5.3)** |
| `uploads/` | uploaded files, uuid file ids | per-file owner (index), flat dir |
| `personal_docs/`, `personal_docs/runbook/` | personal documents | per-user (doc rows) |
| `personal_uploads/` | personal uploads | per-user |
| `generated_images/` | generated images | per-user (gallery rows) |
| `gallery/`, `gallery_uploads/` | gallery media | per-user (gallery rows) |
| `deep_research/` | deep research outputs | per-user |
| `rag/`, `chroma/`, `memory_vectors/`, `fastembed_cache/` | vector stores | shared indexes, rows owner-scoped |
| `emoji_cache/`, `tts_cache/`, `cache/`, `process_resources/`, `browser_resources/` | caches/resources | global (no user data) |
| `mcp_oauth/` | MCP OAuth tokens | per-user |
| `mail-attachments/` | email attachments | per-user (email account) |
| `skills/` | installed skills | per-user |
| `hwfit/`, `logs/`, `local/`, `bg_jobs/` | misc/logs | global |

### 2.4 Sidebar sections → where their data lives

Frontend: `static/index.html` shell + `static/app.js` orchestrator +
`static/js/*` modules (97 files). Sidebar sections and storage:

| Sidebar section | Data store(s) |
|---|---|
| Chat (sessions) | `sessions`, `chat_messages` (DB) |
| Calendar | `calendars`, `calendar_events`, `caldav_deleted_events`, `email_calendar_invitations` (DB); `tidy_calendar_state.json` |
| Compare | `comparisons` (DB) |
| Cookbook | `cookbook_state.json` + local code dirs |
| Deep Research | `deep_research/` + chat sessions |
| Documents (Library) | `documents`, `document_versions` (DB); `personal_docs/` |
| Email | `email_accounts` (DB), `scheduled_emails.db`, `email_cache.db`, `mail-attachments/`, `contacts.json` |
| Gallery | `gallery_albums`, `gallery_images` (DB); `gallery/`, `generated_images/` |
| Memory | `memories` (DB); `memory.json`, `memory_vectors/` |
| Notes | `notes` (DB) |
| Skills | `user_tools`, `user_tool_data` (DB); `skills.json`, `skills/` |
| Tasks (scheduled) | `scheduled_tasks`, `task_runs` (DB); `bg_jobs.json`, `bg_jobs/` |
| Settings | `settings.json`, `user_prefs.json`, `features.json`, `api_tokens` (DB) |
| Admin | `auth.json`, `mcp_servers`, `webhooks` (DB), `vault.json`, `embedding_endpoint.json` |

## 3. Existing auth architecture (current state)

- `AuthMiddleware` (`app.py` ~line 404): sets `request.state.current_user`.
  Sources: session cookie → `sessions.json`; bearer `ody_` token →
  `current_user="api"` + `api_token_owner`; internal-tool loopback token →
  `X-Odysseus-Owner` attribution; `LOCALHOST_BYPASS` (loopback only, disabled).
- **Auth-exempt** (`app.py` ~lines 305–329):
  - Exact: `/api/auth/{setup,signup,login,logout,status,features,settings}`,
    `/api/auth/integrations/presets`, `/api/health`, `/api/version`, `/login`
  - Prefix: `/static`
  - Pattern: `^/api/tasks/[^/]+/webhook/[^/]+/?$` (token in path — external
    callers; **kept**, documented)
- Unauthenticated: `/api/*` → 401 JSON; other paths → 302 `/login`.
- SPA: `static/app.js:204` fetch patch → 401 → `window.location='/login'`.
- `create_session_trusted(username)` (`core/auth.py:594`) — issues a session
  token for a verified username without a password check. **This is the SSO
  hook.**
- Users in `data/auth.json`: `su1@vr2.in` (is_admin), `it2@vr2.in`,
  `it5@vr2.in`.

## 4. SSE / streaming endpoints (no true inbound WebSockets)

All owner-scoped via `request.state.current_user` in handler:

| File | Lines (EventSourceResponse/streaming) |
|---|---|
| `routes/chat_routes.py` | 2889, 5073, 5081, 5101, 5303 |
| `routes/shell_routes.py` | 1223, 1244, 1249, 1344 |
| `routes/research/research_routes.py` | 709 |
| `routes/model_routes.py` | 2016, 2054, 2505 |
| `routes/editor_agent_routes.py` | 1538 |
| `routes/email/email_routes.py` | 6871 |

SSE connections open inside an already-authenticated request, so the user is
fixed at connect time; handlers must not re-resolve identity from query/body.

## 5. Route owner-coverage audit

`owner` usages per route file (high = well covered):

- **High:** email_routes (536), chat_routes (118), calendar_routes (121),
  skills (95), task_routes (78), contacts (72), document (66), codex (61),
  auth (61), memory, notes, gallery, compare, sessions.
- **LOW / to audit during implementation:**
  - `routes/search/search_routes.py` (owner:0)
  - `routes/admin_wipe_routes.py` (1)
  - `routes/cleanup_routes.py` (1–2)
  - `routes/hwfit_routes.py` (1 — admin-gated)
  - `routes/preset_routes.py` (1)
  - `routes/shell_routes.py` (1)
  - `routes/webhook_routes.py` (1 — global by design)
  - `routes/backup_routes.py`, `routes/diagnostics_routes.py` — check gating

## 6. SSO design (Authentik)

### 6.1 Identity mapping

- **Local username = verified email, lowercased** (`sub` is the stable key).
  Existing local users are already email-named (`su1@vr2.in`, …), so
  **legacy data needs no ownership migration** — the same usernames match.
  Fallback if email missing/ambiguous: sanitized local-part + 8-hex
  `sha256(sub)` slug.
- User record in `auth.json` gains: `sso: {sub, email, groups[], first_sso}`.
  `password_hash` kept (harmless) but password login disabled (below).
- **Role:** `is_admin = True` iff groups contain `odysseus-admins`
  **or** email == `su1@vr2.in`.
- Provisioning: on first SSO login, create local user (with a random
  unusable password hash) iff the user passed Authentik's group-membership
  policy. No local signup.

### 6.2 Authentik objects (created via API, never guessed)

- Groups: `odysseus-admins` (member: `su1@vr2.in`), `odysseus-users`.
- OAuth2 **provider** slug `odysseus`: confidential client, redirect URI
  `https://12353.vr2.in/auth/callback`, authorization scopes
  `openid profile email groups`, signing key = default self-signed RS256
  (from `/api/v3/crypto/`), `include_scope_in_id_token` on, groups claim in
  ID token.
- **Application** slug `odysseus`, issuer `https://12390.vr2.in/application/o/odysseus/`.
- **Policy binding** on the application: expression policy — user is member
  of `odysseus-admins` or `odysseus-users` (checked from the
  `groups` claim / user's group memberships), else login denied.
- Client ID/secret → `.env` (chmod 600). Random session secret → `.env`.

### 6.3 OIDC flow implemented in Odysseus

- New `core/sso.py`: discovery (cached), PKCE S256, state/nonce in a short-TTL
  server-side store (signed), code exchange, ID-token verification via JWKS
  (RS256: signature, `iss`, `aud`, `exp`, `nonce`), user provisioning.
  Reference implementation already proven against this same Authentik:
  `~/.config/systemd/user/dsh-gateway.py` (PKCE + JWKS RS256).
- New `routes/sso_routes.py`:
  - `GET /auth/login` → build auth URL, 302 to Authentik.
  - `GET /auth/callback` → verify, `create_session_trusted(username)`, set
    cookie, 302 `/`.
  - `GET /auth/logout` → revoke session, clear cookie, 302 `/auth/login`.
- **Cookie:** `SESSION_COOKIE` (existing name), `HttpOnly`, `Secure`,
  `SameSite=Lax`, signed (app key). Secure is enforced for this deployment
  (behind TLS proxy; `COOKIE_SECURE` env, default on when SSO enabled).
- **Middleware changes (`app.py`):**
  - Add `/auth/login`, `/auth/callback` to `AUTH_EXEMPT_EXACT`.
  - `GET /login` (and the SPA 401 target) → 302 `/auth/login` when SSO on.
  - Proxy header trust: uvicorn behind cloudflared — `--proxy-headers` /
    `FORWARDED_ALLOW_IPS` so `X-Forwarded-Proto` is honored (HSTS + Secure
    cookies + correct redirect URIs).
- **Password login disabled when SSO on:** `POST /api/auth/login`,
  `/api/auth/signup`, `/api/auth/setup` return 403 (exempt paths stay exempt
  so the SPA's status check works; body says "SSO only").
- **Migration (one-time, at SSO enable):** purge all tokens in
  `data/sessions.json` — only SSO-issued sessions are valid afterwards.
  (3 live sessions exist at time of writing; users simply re-login via SSO.)
- **Kept (documented decisions):**
  - Bearer `ody_` API tokens (admin-minted, owner-attributed, scoped).
  - Task webhook URLs (token in path, external callers).
  - Internal-tool loopback token (in-process, random per boot).
  - `LOCALHOST_BYPASS` stays **false**.

## 7. Per-user isolation design

### 7.1 Central rule

The app's native multi-user model IS the isolation model: `owner` column =
user id (username). Enforced in ONE place per layer:

- **DB:** `owner_filter(query, model_cls, user)` (`src/auth_helpers.py`) —
  already the central DB filter. Implementation audit: every route touching
  an owner-scoped table must call `require_user` + `owner_filter`; child
  tables (chat_messages, calendar_events, task_runs, document_versions,
  user_tool_data) are reached **only through their parent's id**, and the
  parent lookup is owner-filtered.
- **New `core/isolation.py`:**
  - `assert_owner(request, owner_value, *, admin_bypass=True)` — direct
    object access by id (GET/PUT/DELETE /resource/{id}) returns **404**
    (not 403 — don't leak existence) when `owner_value` is not the current
    user; admins pass (and are audit-logged, §8).
  - Per-user path helpers for file stores.
  - `audit_admin_cross_user(event)` → `data/admin_audit.log` (JSON lines).
- **Current user always from server session** — never from query/body/header
  (except the documented internal-tool attribution, loopback-only).

### 7.2 File sandbox

- Agent file tools already resolve against the active workspace and
  containment blocks escapes; **default workspace becomes per-user** (below).
- Uploads: per-file owner already enforced (`_verify_upload_access` in
  `routes/upload_routes.py` download + delete paths) — audit all upload
  routes for the same check.
- Path-traversal defense: all user-facing file endpoints take opaque ids
  (uuid file ids, DB ids), not paths — verified for uploads; same pattern
  kept for gallery/personal_docs (DB-id based).

### 7.3 Per-user agent workspace

- `src/tool_execution.py` default workspace root
  (`os.path.realpath(AGENT_WORKSPACE_DIR)` ~line 1270) changes to
  `data/agent_workspace/<owner>/` when an owner is present (single-user /
  no-owner mode keeps the shared root for backward compat).
- Legacy `data/agent_workspace/*` contents are pre-existing su1 data →
  moved to `data/agent_workspace/su1@vr2.in/` in the one-time migration
  (only if non-empty; documented in the runbook section of this file).

### 7.4 Streaming + background jobs

- SSE handlers: identity fixed at connect (authenticated request); no
  re-resolution. Audit each of the 12 listed endpoints.
- Background jobs (`bg_jobs.json`, `background_tool_jobs` table): job records
  carry `owner`; poller/runner must execute with the owner's context
  (workspace + filters) — verified during implementation; the table already
  has an owner column.
- Scheduled tasks / task webhooks: webhook token identifies the task; task
  row is owner-scoped; execution runs as the task owner.

## 8. Admin view (su1@vr2.in)

- **Impersonation ("view as"):**
  - `POST /api/admin/impersonate {username}` — admin only (403 otherwise);
    stores `impersonating: <username>` on the **current session record**
    (`sessions.json` — plain dicts, extra keys are fine).
  - `POST /api/admin/impersonate/stop` — clears it; **checks the real admin
    identity** (session's original username, not the impersonated one).
  - `AuthMiddleware`: after resolving the session, if the session has
    `impersonating` **and** the real user is admin →
    `request.state.current_user = <target>`,
    `request.state.admin_actual_user = <real>`.
  - While impersonating: admin can read/modify the target's data (all
    `assert_owner` checks pass via admin bypass, which uses
    `admin_actual_user` when set).
- **Admin-only API/UI:** `GET /api/admin/users` (list all users + data
  counts), user switcher in `static/js/admin.js` users tab ("View as …"
  button), persistent banner "Viewing as <user> — stop" injected by a small
  frontend module (reads `/api/auth/status` which reports
  `impersonating` + `is_admin`).
- **Audit:** every admin cross-user access (impersonate start/stop, and
  admin-bypassed `assert_owner` hits) appended to `data/admin_audit.log`.
- Non-admins hitting admin endpoints: 403.

## 9. Environment variables (new, in `.env`, chmod 600)

| Var | Purpose |
|---|---|
| `SSO_ENABLED` | `true`/`false` master switch (default false until set) |
| `SSO_ISSUER` | `https://12390.vr2.in/application/o/odysseus/` |
| `SSO_CLIENT_ID` | Authentik application client id |
| `SSO_CLIENT_SECRET` | Authentik application client secret |
| `SSO_ADMIN_GROUP` | `odysseus-admins` |
| `SSO_USER_GROUPS` | `odysseus-admins,odysseus-users` |
| `SSO_ADMIN_EMAIL` | `su1@vr2.in` (hard admin fallback) |
| `SSO_SESSION_SECRET` | random 32+ bytes, signs state/nonce + cookie |
| `COOKIE_SECURE` | `true` (default when SSO enabled) |

Existing: `APP_BIND=0.0.0.0`, `APP_PORT=12353`, admin seed vars,
`ODYSSEUS_EDITOR_DRAFT_MAX_BYTES`.

## 10. How to add a new user (operational runbook)

1. In Authentik (`https://12390.vr2.in/if/`), create the user (email must be
   the address you want as the Odysseus username, lowercased).
2. Add the user to group **`odysseus-users`** (and to
   **`odysseus-admins`** if they should be an admin).
3. Done — on first login at `https://12353.vr2.in` the local Odysseus user
   is provisioned automatically and their data is isolated from everyone
   else. No local account creation, no password.
4. Removing access: remove group membership (or delete the user). Existing
   local data remains on disk, orphaned, until an admin decides.

## 11. Test plan (STEP 7 — results to be appended here)

a. Unauthenticated → browser redirect to SSO / API 401
b. User A sees only own data; creates chat/task/memory/file → visible to A only
c. User B cannot see A's data; id guessing → 404/403; path traversal blocked
d. su1 sees all users + can switch context; banner shows
e. Non-group user cannot log in (Authentik denies)
f. Logout works; session token not reusable
g. Legacy data intact and owned by su1@vr2.in

## 12. File change plan + backups

**Backups before edits** (in `/home/realmont/services/odysseus/.backup-sso-<date>/`):
`app.py`, `core/auth.py`, `core/middleware.py`, `src/auth_helpers.py`,
`src/tool_execution.py`, `routes/auth_routes.py`, `static/app.js`,
`static/js/admin.js`, `data/auth.json`, `data/sessions.json`, `.env`,
and the low-owner route files being edited.

**New files:** `core/sso.py`, `core/isolation.py`, `routes/sso_routes.py`.
**Edited:** `app.py` (exempts, /login redirect, impersonation resolution,
proxy headers), `routes/auth_routes.py` (disable password auth, admin
impersonate endpoints, status reports impersonating), `src/tool_execution.py`
(per-user workspace default), `src/auth_helpers.py` (assert_owner wiring,
impersonation-aware effective user), frontend (`static/js/admin.js` view-as
button, small banner module), `.env` (SSO vars).
**Migration script (one-time):** session purge + `agent_workspace` →
`agent_workspace/su1@vr2.in/` move + record in this file's appendix.

**Restart:** only `odysseus.service` (systemd user unit). Never touch
12343/12344/12363/12390/12391/12393 or the Cloudflare tunnel config.

---

# 13. Implementation results (2026-11-03 → 2026-11-04)

**Status: COMPLETE. All STEP 7 tests (a)–(g) PASS. Live on 12353.**

## 13.1 Authentik objects (created 2026-11-03, verified in UI)

| Object | Name / slug | pk | Notes |
|---|---|---|---|
| Group | `odysseus-admins` | `eb523dc8-83d8-4093-8a9d-1e2a13b846d2` | member: Su1 (`su1@vr2.in`) |
| Group | `odysseus-users` | `de133528-b0be-4b48-b46f-7f245c00d800` | empty (add users here to grant access) |
| OAuth2 provider | `odysseus` | 3 | confidential; strict redirect `https://12353.vr2.in/auth/callback`; scopes `openid profile email groups`; RS256 via bound "authentik Self-signed Certificate"; client id `2gS6hzuOfgKJDtXXdjbgmfCgjS3LXw1zFTo21Kkj` (secret only in `.env`) |
| Scope mapping | `Odysseus groups scope` | — | emits `groups` claim into the token |
| Application | `Odysseus` (slug `odysseus`) | `fc26d336-78ef-4382-aa66-11af7c849236` | issuer `https://12390.vr2.in/application/o/odysseus/` |
| Expression policy | `odysseus-access` | `6f4b247a-4b97-49d6-8301-bfb079002c4e` | see CRITICAL fix below |
| Policy binding | (unnamed) | `7ae61708-cd9d-444f-8d50-78c40bfa0264` | on Application `Odysseus`, enabled, not negated, order 0 |

No existing Authentik user, group, application, flow, or password was
modified or deleted (only the new objects above; Su1 added to
`odysseus-admins`).

### CRITICAL fix (2026-11-04): expression policies must contain `return`

Authentik 2026.8.5 wraps an expression policy as the **body** of
`def handler(<ctx>): <expression>` (`lib/expression/evaluator.py:
wrap_expression`). The original `odysseus-access` expression was a bare
expression (no `return`), so the handler returned `None` → policy
`passing=False` for **everyone** — nobody could have logged in, silently.

- Fixed by prepending `return ` (DB backed up first — see §13.5):
  ```python
  return request.user.is_active and (request.user.groups.filter(name='odysseus-users').exists() or request.user.groups.filter(name='odysseus-admins').exists())
  ```
- Verified by live evaluation (`ExpressionPolicy.passes(PolicyRequest(user))`):
  Su1 → **ALLOW**, Swetha (`it2@vr2.in`) → **DENY**,
  Manikandan (`it5@vr2.in`) → **DENY**. All other working policies on this
  instance (`hermes-access`, `open-webui-access`, `deepseek-allow-active`)
  confirm the `return` convention.
- Note: `it2@vr2.in` / `it5@vr2.in` have local Odysseus accounts (created
  during testing) but are **not** in any odysseus group, so SSO login is
  denied for them until they are added to `odysseus-users` in Authentik.

## 13.2 Odysseus files changed / created

**New:** `core/sso.py` (discovery, PKCE S256, state/nonce, code exchange,
JWKS RS256 verify of iss/aud/exp/nonce, identity mapping, provisioning,
role mapping), `core/isolation.py` (`assert_owner`, per-user path helpers,
admin audit log), `routes/sso_routes.py` (`/auth/login`, `/auth/callback`,
SSO logout).

**Edited** (pre-edit copies in `.backup-sso-2026-11-03/`):
`app.py` (auth-exempt `/auth/*`, `/login` → SSO redirect, impersonation
resolution in middleware, proxy-header trust), `core/auth.py`
(`create_session_trusted` used by SSO; session persistence),
`core/middleware.py`, `core/atomic_io.py` (**2026-11-04**: temp files
chmod 0600 before `os.replace` — persisted JSON such as `sessions.json`
with live session tokens and `auth.json` with password hashes is no longer
world/group-readable after each rewrite; `tests/test_atomic_io.py`: 15
passed), `src/auth_helpers.py` (impersonation-aware `effective_user`,
`assert_owner` wiring), `src/tool_execution.py` (per-user agent workspace
`data/agent_workspace/<owner>/` with realpath containment),
`routes/auth_routes.py` (password login/signup/setup → 403 when SSO on;
`/api/admin/impersonate`, `/api/admin/impersonate/stop`,
`/api/admin/users`; `/api/auth/status` reports `impersonating`,
`real_is_admin`, `real_username`), `routes/session_routes.py`
(owner-verified session access), `routes/memory/memory_routes.py`
(owner-scoped memory), `static/app.js`, `static/js/admin.js` (user
switcher + "Viewing as" banner), `static/js/init.js`, `.env` (SSO_* vars,
`SECURE_COOKIES=true`, chmod 600).

## 13.3 STEP 7 test results (all PASS, 2026-11-04)

- **(a) Unauthenticated** — `GET /` → 302 `/auth/login` → Authentik
  authorize URL (client_id, strict redirect_uri, PKCE `code_challenge`,
  `state`, `nonce`); unauthenticated API → 401 JSON;
  `POST /api/auth/login|signup|setup` → 403 "SSO only".
- **(b) User A own data** — user A created a chat session and a memory
  entry (`POST /api/memory/add`, JSON body); both visible to A;
  `GET /api/memory` returns only A's entries.
- **(c) User B isolation** — B's session list excludes A's; A's session id
  via `GET /api/session/{id}/export` and `/context_info` → **404**;
  A's memory id → **404** even for admin su1 not impersonating (memory
  routes have **no admin bypass** — by design, stricter than
  `assert_owner`). Path traversal: `_owner_workspace_dir(owner)` unit test
  — blocked `..`, `../x`, absolute paths, nested `a/b`, symlink escape
  (symlink pointing outside base), sentinel owners (`api`, `demo`,
  `system`, internal tool user), `~`, empty/whitespace; valid owner names
  allowed.
- **(d) Admin su1** — plain cross-user direct API access **without**
  impersonation → 404 (route-level owner guard is stricter than the core
  admin bypass; documented). Impersonation cycle:
  `POST /api/admin/impersonate {"username": it2}` → `/api/auth/status`
  shows `impersonating=it2@vr2.in`, `is_admin=false`,
  `real_is_admin=true`, `real_username=su1@vr2.in`; while impersonating,
  su1 sees exactly A's data (B's ids → 404); `/impersonate/stop` restores
  su1. `data/admin_audit.log` records `impersonation_start`/`stop`.
  Non-admin → 403 on all `/api/admin/*`; unauthenticated → 401.
- **(e) Non-group user** — policy evaluated live against real users:
  Su1 (in `odysseus-admins`) ALLOW; Swetha, Manikandan (in neither group)
  DENY; binding verified enabled/non-negated on the application.
- **(f) Logout** — `POST /api/auth/logout` → 200, cookie cleared, token no
  longer authenticates (401); other users' sessions unaffected.
- **(g) Legacy data** — su1's legacy session `hello`
  (`cc7fcbc6-de84-4450-9dae-5926665f87eb`) and `Assistant`
  (`a98d78df-7c22-4629-924b-9f755883fdd5`) intact, owned
  `su1@vr2.in`; `model_endpoints` rows NULL-owner (shared by design);
  `data/agent_workspace/` root empty (no legacy move needed); it2/it5 rows
  are auto-provisioned per-user defaults (one `Assistant` session each),
  correctly owner-scoped.
- **SSO crypto suite** — 22/22 passed (JWKS fetch, RS256 signature,
  iss/aud/exp/nonce checks, PKCE verifier, state/nonce replay rejection,
  provisioning, role mapping, cookie flags).

## 13.4 Test-data cleanup (2026-11-04)

All test rows deleted **via owner APIs** (session A + memory entry by
user A; session B by user B after a short-lived re-issued test session):
`data/app.db` now contains only legacy su1 rows + the two
auto-provisioned per-user `Assistant` sessions. All test auth tokens
revoked through the service-side `POST /api/auth/logout`;
`data/sessions.json` == `{}` (mode 600). All `/tmp` test scripts, helper
scripts, and the temporary RSA test key deleted. Service restarted
(`systemctl --user restart odysseus`) — `active`, 12353 responding,
unauthenticated `/api/auth/status` → 200 `authenticated:false,
sso_enabled:true`.

## 13.5 Backups

| Path | What |
|---|---|
| `/home/realmont/backups/odysseus/2026-11-03_pre-sso` | full Odysseus folder + DB (733 MB) before any code change |
| `/home/realmont/services/odysseus/.backup-sso-2026-11-03/` | per-file pre-edit copies: `app.py`, `core/auth.py`, `core/atomic_io.py` (added 2026-11-04), `routes/auth_routes.py`, `src/auth_helpers.py`, `src/tool_execution.py`, `static/js/admin.js`, `static/js/init.js`, `data/auth.json`, `data/sessions.json`, `.env.pre-sso` |
| `/home/realmont/backups/authentik/2026-11-03_123131` | Authentik `pg_dump` before object creation |
| `/home/realmont/backups/authentik/2026-11-04_204110_pre-policy-return-fix/authentik_pre-policy-return-fix.sql` | (21.8 MB) taken immediately before the `odysseus-access` `return` fix |

## 13.6 Operational notes

- **Restarted only `odysseus.service`** (systemd user unit, enabled →
  auto-starts after reboot). Cloudflare tunnel (gx10-1) and all other
  services untouched.
- Trust proxy headers: uvicorn `--proxy-headers` +
  `FORWARDED_ALLOW_IPS=127.0.0.1` (cloudflared connects via loopback) —
  `X-Forwarded-Proto` honored, Secure cookies work end-to-end.
- Session tokens are the cookie value itself (no separate session secret
  needed beyond `SSO_SESSION_SECRET` for state/nonce signing);
  `sessions.json` holds them and is now always written 0600.
- Adding a user: add their Authentik user to `odysseus-users` (or
  `odysseus-admins`) — first login provisions the local account
  (runbook §10). Removing access: remove the group membership.

---

# 14. "Only su1 can log in" — diagnosis (2026-11-05)

Reported: Odysseus is connected to Authentik but only `su1@vr2.in` can get
in. Read-only diagnosis of both sides:

## 14.1 Authentik side (ak shell, read-only)

- Application **Odysseus** (`fc26d336-…`, slug `odysseus`): policy engine
  mode `any`, bound policies: `odysseus-access`.
- Policy binding `7ae61708-…`: policy `odysseus-access`, **enabled**,
  **not negated**, not dry-run, order 0 → the policy IS the access gate.
- Expression policy `odysseus-access` (fixed form with `return`, per §13.1):
  allow iff user is active AND in `odysseus-users` OR `odysseus-admins`.
  So the application is bound to **both** groups as required.
- **`odysseus-admins` members: Su1 (`su1@vr2.in`) only.**
- **`odysseus-users` members: NONE (empty group).** ← root cause
- Provider `odysseus`: confidential, strict redirect
  `https://12353.vr2.in/auth/callback`, RS256 "authentik Self-signed
  Certificate", `include_claims_in_id_token=True`, sub = hashed user id.
  Property mappings: `openid`, `email`, `profile`, plus **Odysseus groups
  scope** (`return {"groups": [...]}`) — the `groups` claim is present in
  the ID token and userinfo. Client secret is set (value never printed).
- User inventory (username | email | active | type | groups):
  - Su1 | su1@vr2.in | yes | internal | authentik Admins, deepseek-admins, hermes-admins, **odysseus-admins**, open-webui-admins
  - Swetha | it2@vr2.in | yes | internal | — (no groups)
  - Manikandan | it5@vr2.in | yes | internal | — (no groups)
  - AnonymousUser | — | yes | internal | — (no email; special account)
  - dsh-test-a | dsh-test-a@vr2.in | yes | internal | — (dedicated DeepSeek-Harness test account)
  - dsh-test-b | dsh-test-b@vr2.in | yes | internal | — (ditto)
  - dsh-deny | dsh-deny@vr2.in | **no** | internal | — (inactive deny-test account)
  - hermes-user-b | hermes-user-b@vr2.in | yes | internal | hermes-users
  - hermes-deny | hermes-deny@vr2.in | yes | internal | — (hermes deny-test account)
  - owui-user-a | owui-user-a@vr2.in | yes | internal | open-webui-users
  - owui-user-b | owui-user-b@vr2.in | yes | internal | open-webui-users
  - owui-deny | owui-deny@vr2.in | yes | internal | — (owui deny-test account)
  - ak-outpost-7c9e… | — | yes | internal_service_account | — (service account, excluded)

## 14.2 Odysseus side (code review)

- `core/sso.py`: **no allowlist, no hard-coded su1-only check.** The
  `su1@vr2.in` comparison only sets the *admin role* (fallback so the admin
  can never be locked out), it does not gate login.
- Identity: local username = verified `email` claim, lowercased; the
  `sub` claim (hashed user id in this provider) is stored as SSO metadata
  (`auth.json` → `users.<name>.sso.sub`) and refreshed on every login.
  `sub` ↔ email is 1:1 in this Authentik, so the account key is stable.
- First login: `provision_local_user` **auto-creates** the local account
  (random unusable password; password login is disabled in SSO mode).
- **Gap found (fixed in §15):** Odysseus never re-checked the `groups`
  claim — a token without the right groups (e.g. policy misconfigured)
  would have been provisioned as a regular user. Defense in depth: the
  callback now refuses any user in neither `odysseus-users` nor
  `odysseus-admins` (su1@vr2.in email fallback preserved).
- Missing/malformed `groups` claim → treated as no groups → refused after
  the §15 fix (previously: provisioned as regular user).

## 14.3 Logs (`logs/odysseus.log`)

- 2026-11-05: four **successful** SSO logins, all `su1@vr2.in`
  (09:14, 10:24, 14:48, 14:59) — the flow works end-to-end for an allowed
  user.
- **Zero failed callbacks from non-admin users** — because the denial
  happens earlier: the `odysseus-access` policy rejects them at the
  Authentik authorize step, so they never reach the token endpoint or the
  Odysseus callback. Consistent with an empty `odysseus-users` group.
- (Historical, 2026-11-04 16:00–17:15: "Issuer mismatch on discovery
  document" — the trailing-slash issuer bug fixed in the prior session;
  no recurrence since.)

## 14.4 Root cause

The access gate is the `odysseus-access` policy (allow = member of
`odysseus-users` OR `odysseus-admins`). `odysseus-admins` contains only
Su1, and **`odysseus-users` is empty** — the group was created but no one
was ever added to it (the add-user step was awaiting confirmation at the
end of the previous session). Nothing in the Odysseus code restricts login
to su1. Fix: add the intended users to `odysseus-users` (STEP 2 below) +
server-side group re-check in the callback (STEP 3, §15).

## 15. Access widening: every allowed user can log in (2026-11-05)

### 15.1 Changes made (complete list)

**Authentik (2 group memberships, nothing else):**
- `it2@vr2.in` (Swetha) and `it5@vr2.in` (Manikandan) added to
  `odysseus-users` via the admin API, per the user's confirmed choice
  ("Swetha + Manikandan only"). No other account was added — no
  AnonymousUser, no dsh-\*/hermes-\*/owui-\* accounts.
- Application, policy, binding, provider, property mappings: **unchanged**
  (pks as in §14).

**Odysseus (1 file, 1 function):**
- `core/sso.py` → `identity_from_claims`: server-side group gate added.
  Role: admin iff `groups` ∋ `odysseus-admins` OR `email == su1@vr2.in`.
  Access: allowed iff admin OR `groups` ∩ {`odysseus-users`,
  `odysseus-admins`} ≠ ∅; otherwise the callback raises
  `SSOError("You are not authorized to use Odysseus")`. Missing or
  malformed `groups` claim → treated as no groups → refused. Logout and
  the rest of the SSO flow are unchanged.
- Pre-edit copy: `.backup-sso-2026-11-03/core/sso.py` (repo-relative).

### 15.2 Verification

- **Gate unit tests: 10/10 pass** (admin group, admin-email fallback,
  users group, neither-group → refused, missing claim → refused,
  malformed claim → refused, case-insensitive group match, …).
- **Live Authentik policy evaluation** of `odysseus-access` against real
  users: su1, it2, it5 → ALLOW; owui-user-a, hermes-user-b, dsh-deny →
  DENY.
- **Targeted pytest subset: 100/100 pass** (80 SSO tests + 20
  `test_null_owner_gates.py`). Note: that last file reports 20 pre-existing
  *teardown* hygiene errors ("test left bare module stub(s) in
  sys.modules: src.webhook_manager") — bodies pass; the errors reproduce
  when the file is run alone and are unrelated to this change (left as-is,
  out of scope).

### 15.3 STEP 6 live results (service on port 12353)

- **(a) PASS** — not logged in: `/` → 302 `/login` → 302 to the
  Authentik authorize URL (response_type, client_id, redirect_uri,
  scope=`openid profile email groups`, state, nonce, PKCE all present);
  API calls without a session → 401.
- **(b) PASS (9/9)** — it2 logs in, starts with an **empty workspace**,
  creates a chat session, a note and a task; all visible in its own lists.
- **(c) PASS (6/6)** — it5's lists exclude it2's items; ID guessing →
  note 404, task 403, session export 404; path traversal blocked.
- **(d) NOT live-runnable** — no real password available for an
  out-of-group user. Proven instead by (i) live policy evaluation
  (owui-user-a / hermes-user-b / dsh-deny → DENY, so they are refused at
  the Authentik authorize step and never reach the callback) and (ii) the
  10/10 unit tests of the server-side gate (a token for a neither-group
  user is refused at the callback even if one were presented).
- **(e) PASS (9/9)** — su1: `GET /api/admin/users` lists all 3 users;
  impersonate it2 → status shows impersonation → sees it2's note; stop →
  no longer sees it; it2 (non-admin) gets 403 on both admin endpoints.
- **(f) PASS (5/5)** — legacy data intact and owned by su1: su1's
  `hello` session and hidden default `Assistant` session both open
  (export 200); it5 gets 404 on both. (Default `Assistant` sessions are
  hidden from the list view by design — verified via owner-scoped
  single-item access.)
- **(g) PASS (4/4)** — `POST /api/auth/logout` → 200; the token is
  invalid immediately after; other users' sessions unaffected.
- **Not run:** full browser end-to-end with real user passwords (no
  password access). The trusted-session method below exercises the same
  server-side code path from session creation onward.

**Method note for (b)/(c)/(e)/(f)/(g):** trusted test sessions were
created with `AuthManager.create_session_trusted()` — the exact call
`complete_sso_login()` makes after successful OIDC verification — issued
while the service was stopped and loaded at startup. This covers the
session, isolation and admin code paths but not the browser / ID-token
exchange. All test sessions were logged out through the service API and
all throwaway rows deleted; the DB was verified back to baseline
(it2: 11 tasks/1 session, it5: 11 tasks/1 session, su1: 11 tasks/2
sessions, 0 notes, 0 memories).

### 15.4 Finding: stale tokens left in `data/sessions.json` after test cleanup

- **Symptom:** after all test logouts returned 200, `data/sessions.json`
  still held 3 entries (7-day expiry) and the running service **accepted
  them**.
- **Root cause:** not a revoke bug — `revoke_token()` does persist. The
  trusted-session issuer was run multiple times; each run loads the
  existing sessions and adds new ones, so the file accumulated tokens from
  earlier runs. The last logout's save wrote back the older tokens that
  were still in memory (loaded from disk at startup).
- **Fix applied:** service stopped → `data/sessions.json` reset to `{}`
  (mode 600) → service started → all stale and current test tokens
  verified rejected; file remains `{}`.
- **Lesson:** reset `data/sessions.json` to `{}` (service stopped) before
  issuing trusted test sessions, so the file only ever holds the current
  batch.

### 15.5 Backups

- `/home/realmont/backups/odysseus/2026-11-05_pre-access-widen/odysseus`
  — full app + data (736M; service stopped for a consistent DB copy)
- `/home/realmont/backups/authentik/2026-11-05_pre-group-add/authentik_pre-group-add.sql`
  — Authentik DB dump (21.5MB)
- `/home/realmont/services/odysseus/.backup-sso-2026-11-03/core/sso.py`
  — per-file pre-edit copy
- Older (prior sessions): `/home/realmont/backups/odysseus/2026-11-03_pre-sso`
  (733M), `/home/realmont/backups/authentik/2026-11-03_123131`,
  `/home/realmont/backups/authentik/2026-11-04_204110_pre-policy-return-fix`

### 15.6 How to add a new user

1. **Authentik: Directory → Users** — create the user (or pick an
   existing one).
2. **Authentik: Directory → Groups → `odysseus-users`** — add the user.
3. Done — no Odysseus-side step. The first SSO login auto-provisions the
   local account (keyed by the verified email/`sub`; random unusable
   password; role = regular user). For an admin, add the user to
   `odysseus-admins` instead of (or in addition to) `odysseus-users`.

### 15.7 Service commands

```bash
systemctl --user start odysseus      # start
systemctl --user stop odysseus       # stop
systemctl --user restart odysseus    # restart
systemctl --user status odysseus     # status
systemctl --user is-enabled odysseus # → enabled (auto-start after reboot;
                                     #   Linger=yes, Restart=always)
journalctl --user -u odysseus        # journald logs
tail -f /home/realmont/services/odysseus/logs/odysseus.log  # app log
```

## 16. Workspace isolation: full storage + code-execution inventory (2026-11-06)

STEP 1 of the workspace-isolation task. Read-only audit: every place
Odysseus stores files or runs code on a user's behalf, where it stores
them, how the path is built, and whether it is confined to the logged-in
user. No secrets are recorded here.

### 16.1 Central enforcement points (confirmed in code)

1. **Owner identity is always server-side.** Chat turns derive the owner
   from `effective_user(request)` (session cookie → `sessions.json`),
   sealed into a `RequestAuthority` (`src/agent_runtime/authority.py`) and
   passed as `owner=` into `execute_tool_block`
   (`src/tool_execution.py:1747`). It is set into the `_active_owner`
   contextvar exactly once per tool block; no client-supplied value can
   become the owner.
2. **Per-user agent workspace.** `_owner_workspace_dir(owner)`
   (`src/tool_execution.py:1178`) → `data/agent_workspace/<owner>`: raw
   username, direct-child `realpath` check (a symlink or crafted name
   resolving elsewhere is refused), `.`/`..`/separator/`~` names refused,
   request-sentinel owners get no bucket. All agent file tools
   (read/write/edit/grep/glob/ls) resolve through
   `_resolve_tool_path` / `_resolve_tool_path_in_workspace`:
   `expanduser` → `/workspace` alias → `realpath` → app-state deny
   (all of `DATA_DIR` except 5 readable subdirs, symlinks into them
   refused) → sensitive-path deny (`src/agent_runtime/path_policy.py`:
   `.ssh`, `.gnupg`, `.env`, `id_rsa`, `app.db`, …, casefolded) →
   hard-link deny → allowlist containment.
3. **Code execution is fail-closed on this host.** `containment.py` runs
   in `MODE_ENFORCING`: bash/python/background-jobs need the
   FILESYSTEM + PROCESS_TREE dimensions, only bubblewrap provides them,
   and the bwrap probe fails here (see §16.4 host fact). Result:
   **no user — including admins — can execute agent code** through the
   contained path; every attempt returns
   `{"error": "...command not executed", "executed": false}`.
4. **Subprocess env is scrubbed.** `_agent_subprocess_env()`
   (`src/tool_execution.py`) = strict whitelist (PATH, LANG, TERM, …);
   `XDG_*`, `LD_LIBRARY_PATH` excluded; HOME = the owner's workspace.
   No value from `.env` ever reaches a child process.
5. **Row-level access** goes through `core/isolation.py:assert_owner`
   (404, never 403; plain-admin cross-user passes + audit;
   impersonating admin stays in the target's permissions). Impersonation
   start/stop itself is audit-logged (`impersonation_start/stop`,
   `routes/sso_routes.py`).
6. **Static serving.** `app.py` mounts only `/static` (app assets).
   There is no HTTP mount of `data/`; every user file is served through
   an id/DB-gated route.

### 16.2 Storage inventory (area | where | how path is built | confined?)

| Area | Stored in | Path construction | Confined? |
|---|---|---|---|
| Chat sessions/messages | `data/app.db` | DB rows, `owner` column + `owner_filter` | yes (row-level, prior work) |
| Notes / tasks / calendar | `data/app.db` | DB rows, `owner` column | yes (row-level) |
| Uploads (all chat/note/doc attachments) | `data/uploads/YYYY/MM/DD/<server_id>` | server-generated id; display name via `secure_filename`; every read path gates on `validate_upload_id` + recorded `owner` (`routes/upload_routes.py`, `src/upload_handler.py`) | yes — owner check on download; id is not guessable; no filename-in-URL route |
| Gallery images | `data/gallery/` + `data/gallery_uploads/` | DB row per image (`owner`, `filename`); list/search use `_owner_filter`; file served at `/api/gallery/file/{filename}` only after the DB row's owner matches (404 otherwise) | yes |
| AI-generated images | `data/generated_images/<hash-ish name>` | flat; served at `/api/generated-image/{filename}` (`app.py:577`) with fail-closed ownership chain: registration table → GalleryImage owner → session owner → chat-message reference; anything unresolved → 404 | yes — filename is a server name, route 404s on owner mismatch |
| Personal docs / RAG uploads | `data/personal_docs/`, `data/personal_uploads/<owner>/` | per-owner subdirectory; user-supplied paths pass `confine(PERSONAL_DIR, …)` (`routes/personal_routes.py`); username renames propagate (`rename_personal_upload_owner`) | yes — per-user dir + `confine()` |
| RAG vector store | `data/rag/` (Chroma) | flat shared store, chunks carry `owner` metadata | routes are **admin-only** (`require_admin` on every personal-docs RAG endpoint) — regular users cannot query it |
| Deep Research | `data/deep_research/<owner>/` | per-owner subdir; user paths via `confine()` (`routes/research/research_routes.py`) | yes |
| Documents (Library) | `data/app.db` + uploads for sources | DB rows owner-scoped; export-pdf verifies doc owner (`_verify_doc_owner`) then serves a tempfile; upload location via `_locate_current_user_upload` → `resolve_user_upload_path` (id + owner match) | yes |
| Email attachments | `data/mail-attachments/<owner>/<account>/<folder>/<sha1>` | `src/mail_attachment_paths.py`: per-(owner,account,folder,uid) hashed dir; `require_owner` on every route; post-resolution `realpath` containment | yes |
| Agent workspaces (AI-created files) | `data/agent_workspace/<owner>/` | `_owner_workspace_dir` (see §16.1.2) | yes — see gap G1 for permissions |
| Background jobs | `data/bg_jobs.json` + in-memory capture | job output captured through the contained path (fail-closed, §16.1.3); no per-user output files on disk | yes |
| Skills | `data/skills/` (flat) + `data/skills.json` | owner in `SKILL.md` frontmatter + `owner::skill` usage keys; skill routes owner-scoped; rename propagates | yes (metadata-level) |
| Notes images | via uploads system (id reference in note content) | same as uploads | yes |
| TTS/emoji/email-urgency/fastembed caches | `data/tts_cache/` etc. | shared app caches, no user content | n/a (no user data) |
| Browser/process resources | `data/browser_resources/`, `data/process_resources/` | app-internal, no user-facing route | n/a |
| Sessions/auth/settings | `data/sessions.json`, `auth.json`, `app.db`, … | files 0600, `data/` dir 0775 (listing visible to local users; file contents are not) | pre-existing; out of scope, noted |

### 16.3 Code-execution inventory (subprocess sites)

| Site | What runs | User-controlled? | Verdict |
|---|---|---|---|
| Agent bash/python (`src/agent_tools/subprocess_tools.py`) | user commands | yes | contained path only; **fail-closed for everyone on this host** (§16.4); env scrubbed; cwd = owner workspace |
| Agent background jobs (`src/bg_jobs.py` + tool) | user jobs | yes | same contained path — fail-closed |
| `/api/shell/exec`, `/api/shell/stream` (`routes/shell_routes.py`) | PTY/tmux host shell | yes | **admin-only** (`_require_admin` → 403 for regular users); unsandboxed by design (admin = trusted machine owner) |
| `/api/workspace/browse|vet|default` (`routes/workspace_routes.py`) | directory listing | yes (path arg) | admin-only; `realpath`, symlinks not followed for classification, `vet_workspace` rejects sensitive dirs + filesystem roots |
| Scheduled/builtin actions (`src/builtin_actions.py:888`) | `shell=True` command | yes | policy `requires_admin` enforced → non-admin refused; admin-only |
| Task runner shell actions (`routes/task/task_routes.py:469`) | action commands | yes | shell-executing action types blocked for non-admins |
| `document_processor.py:320` (soffice) | fixed argv + user's **upload** path | input path comes from the uploads system (id-addressed) | ok |
| `media_ingress.py` / `media_tools.py` (ffmpeg, yt-dlp) | fixed argv + user-supplied URL/media | URL only; no host path | ok |
| `endpoint_resolver.py` (git), `model_discovery.py` (du), `process_lifecycle.py` (kill), `builtin_mcp.py` (server argv) | fixed argv | no host paths from users | ok |
| `core/platform_compat.py` (terminal open) | fixed argv (xdg-open etc.) | no | ok |

No `shell=True` with user input outside the admin-gated sites above. No
code path uses the app dir or a shared folder as the default workspace
for an owned turn — owned turns always get
`data/agent_workspace/<owner>`; only ownerless/sentinel turns use the
shared root (documented behavior, not a leak: those turns have no user
identity to confine).

### 16.4 Host fact: why agent code execution is fail-closed

`/usr/bin/bwrap` 0.9.0 exists, but the namespace probe fails:
`bwrap: setting up uid map: Permission denied` (also
`unshare -Ur` → `write failed /proc/self/uid_map: Operation not
permitted`). Sysctls: `kernel.unprivileged_userns_clone = 1`, but
**`kernel.apparmor_restrict_unprivileged_userns = 1`** — AppArmor
blocks unprivileged user namespaces for uid 1000. Consequence:
bubblewrap unavailable → `process_group` mechanism provides only
WALL_CLOCK → enforcing mode refuses every agent command for every user.

Enabling it later (needs sudo):
`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`
(persistent: `/etc/sysctl.d/` drop-in), then restart Odysseus. **Before
enabling**, the bwrap layout must be hardened:
`src/agent_tools/subprocess_tools.py` currently binds `/home` (and
`/mnt`) read-only into the namespace, which would let a contained
command read other users' workspaces and the Odysseus app dir (incl.
`.env`). The fix (dropping `/home` from the bind + mounted-roots,
keeping it reserved) is part of the STEP 2 changes.

### 16.5 Gaps found (STEP 1) → fixed in STEP 2

- **G1 — per-user workspaces world-readable + created late.**
  `default_agent_workspace()` / `_resolve_search_root()` call
  `os.makedirs(owner_dir, exist_ok=True)` with the service umask (002)
  → directories created **0755/0775 (world-readable)**; and only on
  first tool use, not at login. Fix: `provision_user_workspace()`
  (mode 0700 + idempotent chmod) called from `complete_sso_login`
  provisioning, local `create_session`, and from the on-demand path.
- **G2 — no admin workspace view + no cross-user audit for it.**
  Admins could reach a user's workspace only via impersonation + agent
  file tools (labeled "Viewing as <user>" by the existing banner),
  and that path wrote no per-access audit. Fix: dedicated admin-only
  API `GET /api/admin/workspaces/<user>/files[?path=]` (+ raw read),
  every call `audit_admin_cross_user`; impersonating admins get 404
  (consistent with `assert_owner`); plus a per-turn audit event when an
  impersonating admin starts an agent turn.
- **G3 — future bwrap leak (latent).** `/home` ro-bind inside the
  namespace would expose all users' trees once userns is enabled.
  Fixed now (no effect until bwrap works).
- **G4 — shell/agent decision.** Regular users already get
  403/blocked for all shell + file tools (`bash`, `python`,
  `read_file`, … in `NON_ADMIN_BLOCKED_TOOLS`; shell routes
  `require_admin`). On this host even admins' agent commands are
  refused (fail-closed, §16.4) — the strongest no-sudo posture.
  Decision: **keep it**; enable later only via the sudo step in §16.4
  + the G3 hardening (already applied).

### 16.6 How to enable shell safely (later, needs sudo) + test results

**Enablement (requires sudo; not done in this task):**

1. `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`
   (persist via `/etc/sysctl.d/99-allow-userns.conf` if desired).
2. Restart the service: `systemctl --user restart odysseus`.
3. Verify bwrap works: containment probe should report `bwrap` as the
   enforcing mechanism (previously failed: AppArmor blocks unprivileged
   user namespaces → fail-closed, §16.4).

After that: regular users still get **no** shell/agent execution —
`NON_ADMIN_BLOCKED_TOOLS` (`src/tool_security.py`) keeps every
execution + server-file tool admin-gated, and `/api/shell/exec` stays
`require_admin`. Only real admins gain working agent command execution,
inside the bwrap namespace with the G3 hardening applied (no `/home`
ro-bind; per-user workspace bind only). Re-run the §16.6(b) escape
matrix as admin before trusting it.

**Test results (2026-11-09, throwaway users, all data removed after):**

| # | Area | Result |
|---|------|--------|
| a | Cross-user storage (uploads, gallery, libraries, guessed/invalid names) | 10/10 PASS |
| b | Agent file-tool escape attempts (ReadFile/WriteFile: `../../`, absolute, URL-encoded, symlinks, `/etc/passwd`, `data/app.db`) | 15/15 PASS — every escape rejected, nothing written outside owner dir |
| c | Subprocess env hygiene (allowlist, no secret-named keys, no service secret values, HOME=owner ws) + tool gating (regular user: exec/file tools hidden from agent loop, bash/python "restricted to admin"; admin: fail-closed) | 15/15 PASS |
| d | Background jobs (`#!bg`, manage_bg_jobs): regular user admin-gated; admin fail-closed with **no** job record/log/supervisor created | 8/8 PASS |
| e | G2 admin workspace view: admin list/raw 200; A/B 404; path traversal 404; impersonating admin 404 (views) + 403 (shell/exec); stop impersonation restores; regular user shell/exec 403; real admin shell/exec 200; audit log gained `admin_cross_user_access` (admin + real_admin + resource_owner correct) and `impersonation_start/stop` | 18/18 PASS |
| f | Post-cleanup state vs baseline: file tree (zero new files; only WAL/SHM removed by checkpoint), DB row counts (all tables identical to baseline), `sessions.json` (exactly the 3 pre-existing tokens), `auth.json` (exactly the 3 real users), zero `test%-owned rows across all 36 tables | PASS |

Existing isolation (chats/notes/tasks) re-verified by a targeted pytest
batch (17 files): **188 passed, 6 skipped**. Two pre-existing failures
NOT caused by this work: (1)
`tests/test_execution_filesystem_boundary.py::test_probe_and_acquire_agree_on_what_this_host_enforces`
fails on pristine HEAD on this host (AppArmor userns block, §16.4);
(2) 20 teardown hygiene errors in `tests/test_null_owner_gates.py`.

**Test method:** trusted local-session method (direct
`AuthManager.create_user` + session tokens), **no temporary Authentik
users were created**. Scripts: `/tmp/ody-test-c.py`, `/tmp/ody-test-d.py`,
`/tmp/ody-test-e.py`.

**Not driven live:** a full agent turn under impersonation for the
per-turn audit (`admin_cross_user_access`, `what="agent_workspace_turn"`,
`routes/chat_routes.py:3627-3639`) — wiring verified by code inspection
plus the audit sink itself was exercised with a fake request in (e) and
recorded the correct entry.

**Cleanup notes (deliberate):** `data/admin_audit.log` retains the
entries from test (e) — it is an append-only security log and was not
edited. `app.db` is larger in bytes than the pre-test snapshot only
because of SQLite freelist pages after the test-row deletions;
row counts are identical to baseline (see (f)).
