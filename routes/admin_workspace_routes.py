"""Admin-only cross-user browsing of per-user agent workspaces (G2).

``GET /api/admin/workspaces/{username}/files?path=`` lists one directory of a
user's agent workspace; ``GET /api/admin/workspaces/{username}/files/raw?path=``
reads a small regular file. This is the backend for the admin panel's
"Viewing as <user>" workspace viewer — the only sanctioned way an admin
inspects another user's workspace, and every call is audit-logged.

Security rules (aligned with ``core.isolation.assert_owner``):

* Only a REAL, non-impersonating admin may use these routes. While an admin
  is impersonating a user, the target's (non-admin) permissions apply, so
  the route answers 404 exactly like every other cross-user access.
* Non-admins get 404 (never 403): revealing that the route — or that a given
  user's workspace — exists is information leakage.
* Every call appends an ``admin_cross_user_access`` line to
  ``data/admin_audit.log`` before the response is built.
* The ``path`` query is confined to the target user's workspace directory:
  realpath containment, so ``..``, absolute paths, URL-encoded traversal and
  symlinks that point outside the workspace all resolve to 404.
* Listings are capped; raw reads are limited to small regular files.
"""

from __future__ import annotations

import base64
import logging
import os
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request

from core.isolation import audit_admin_cross_user
from src.auth_helpers import get_current_user

logger = logging.getLogger(__name__)

_MAX_LISTINGS = 500
_RAW_READ_CAP = 200 * 1024


def setup_admin_workspace_routes(auth_manager) -> APIRouter:
    router = APIRouter(prefix="/api/admin/workspaces", tags=["admin-workspaces"])

    def _require_real_admin(request: Request) -> str:
        """Gate: real admin only; impersonation and non-admins get 404."""
        if getattr(request.state, "admin_actual_user", None):
            # Impersonating admin: the target's permissions apply.
            raise HTTPException(404, "Not found")
        user = get_current_user(request)
        if not user or not auth_manager.is_admin(user):
            raise HTTPException(404, "Not found")
        return user

    def _resolve(request: Request, username: str, path: Optional[str]):
        """Confine ``path`` to the target user's agent workspace.

        Returns ``(base, target, rel)``. Any escape — unknown user, invalid
        username, ``..``/absolute/URL-encoded traversal, or a symlink that
        resolves outside the workspace — is a 404.
        """
        username = (username or "").strip().lower()
        if not username or username not in auth_manager.users:
            raise HTTPException(404, "Not found")
        from src.tool_execution import _owner_workspace_dir

        base = _owner_workspace_dir(username)
        if base is None:
            raise HTTPException(404, "Not found")
        base = os.path.realpath(base)
        rel = (path or "").strip().lstrip("/")
        target = os.path.realpath(os.path.join(base, rel)) if rel else base
        if target != base and not target.startswith(base + os.sep):
            raise HTTPException(404, "Not found")
        return base, target, rel

    @router.get("/{username}/files")
    def list_workspace_files(request: Request, username: str,
                             path: str = Query(default="")):
        _require_real_admin(request)
        _base, target, rel = _resolve(request, username, path)
        if not os.path.isdir(target):
            raise HTTPException(404, "Not found")
        audit_admin_cross_user(
            request, resource_owner=username, what="agent_workspace",
            action="list", path=rel or None,
        )
        collected = []
        try:
            with os.scandir(target) as it:
                for entry in it:
                    try:
                        is_dir = entry.is_dir(follow_symlinks=False)
                        is_link = entry.is_symlink()
                        size = 0 if (is_dir or is_link) else entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
                    collected.append({
                        "name": entry.name,
                        "is_dir": is_dir,
                        "is_symlink": is_link,
                        "size": size,
                    })
                    if len(collected) > _MAX_LISTINGS:
                        break
        except OSError:
            raise HTTPException(404, "Not found")
        collected.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
        truncated = len(collected) > _MAX_LISTINGS
        return {
            "viewing_as": username,
            "path": rel or None,
            "entries": collected[:_MAX_LISTINGS],
            "truncated": truncated,
        }

    @router.get("/{username}/files/raw")
    def read_workspace_file(request: Request, username: str,
                            path: str = Query(default="")):
        _require_real_admin(request)
        _base, target, rel = _resolve(request, username, path)
        if not rel or not os.path.isfile(target):
            raise HTTPException(404, "Not found")
        try:
            size = os.path.getsize(target)
        except OSError:
            raise HTTPException(404, "Not found")
        if size > _RAW_READ_CAP:
            raise HTTPException(413, "File too large to preview")
        try:
            with open(target, "rb") as f:
                data = f.read()
        except OSError:
            raise HTTPException(404, "Not found")
        audit_admin_cross_user(
            request, resource_owner=username, what="agent_workspace",
            action="read", path=rel, size=size,
        )
        try:
            content = data.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError:
            content = base64.b64encode(data).decode("ascii")
            encoding = "base64"
        return {
            "viewing_as": username,
            "path": rel,
            "size": size,
            "encoding": encoding,
            "content": content,
        }

    return router
