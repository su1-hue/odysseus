"""Central per-user isolation helpers: ownership enforcement + admin audit.

Ownership checks
----------------
:func:`assert_owner` is the single choke point for direct-object access on
routes that fetch a row by id: if the row's ``owner`` differs from the
calling user, the route gets a **404** (not 403) so the existence of other
users' objects is not leaked. A *non-impersonating* admin may cross the
boundary; every such access is appended to the JSON-lines audit log. While an
admin is impersonating another user they see that user's data only — the
target's permissions apply, so cross-user access stays 404.

Audit log
---------
:func:`audit` appends JSON lines to ``data/admin_audit.log``. Written
best-effort: a logging failure must never break the request path, but it is
logged loudly.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import HTTPException, Request

from src.constants import DATA_DIR

logger = logging.getLogger(__name__)

AUDIT_FILE = os.path.join(DATA_DIR, "admin_audit.log")
_AUDIT_LOCK = threading.Lock()


def audit(event: str, request: Optional[Request] = None, actor: Optional[str] = None,
          **details: Any) -> None:
    """Append one JSON line to the admin audit log (best-effort).

    ``actor`` names who performed the action; defaults to the (possibly
    impersonated) current user. Impersonation control endpoints pass the
    REAL admin explicitly because the middleware has already swapped
    ``current_user`` to the target for that request.
    """
    entry: dict = {
        "ts": time.time(),
        "iso": datetime.now(timezone.utc).isoformat(),
        "event": event,
    }
    if request is not None:
        entry["admin"] = actor or getattr(request.state, "current_user", None)
        entry["real_admin"] = getattr(request.state, "admin_actual_user", None)
        client = getattr(request, "client", None)
        entry["client"] = client.host if client else None
        url = getattr(request, "url", None)
        entry["path"] = url.path if url else None
    entry.update(details)
    with _AUDIT_LOCK:
        try:
            os.makedirs(os.path.dirname(AUDIT_FILE), exist_ok=True)
            with open(AUDIT_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except Exception:
            logger.exception("Failed to write admin audit entry for %s", event)


def audit_admin_cross_user(request: Request, resource_owner: str, **details: Any) -> None:
    """Record an admin's cross-user access to someone else's resource."""
    audit("admin_cross_user_access", request, resource_owner=resource_owner, **details)


def assert_owner(request: Request, owner_value: Optional[str], *, what: str = "resource") -> None:
    """Enforce ownership of a directly-addressed object.

    * Caller owns the object -> pass.
    * No owner recorded (legacy/NULL row) -> pass (matches ``owner_filter``
      which also lets NULL-owner 'shared' rows through).
    * Owner mismatch, caller is a plain (non-impersonating) admin -> pass,
      audited.
    * Anything else -> 404. Never 403: revealing that the object exists for
      another user leaks information.
    """
    user = getattr(request.state, "current_user", None)
    if not user or not owner_value:
        return
    if user == owner_value:
        return
    # Mismatch. While impersonating, request.state.admin_actual_user is set
    # and current_user is the target: the target's (non-admin) permissions
    # apply, so this stays a hard 404.
    if getattr(request.state, "admin_actual_user", None):
        raise HTTPException(404, "Not found")
    auth_mgr = getattr(request.app.state, "auth_manager", None)
    if auth_mgr is not None and auth_mgr.is_admin(user):
        audit_admin_cross_user(request, owner_value, what=what)
        return
    raise HTTPException(404, "Not found")
