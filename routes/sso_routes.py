"""Authentik SSO routes + admin impersonation ("View as") controls.

SSO flow
--------
``GET /auth/login``     -> creates a one-time state/nonce/PKCE entry and 302s
                           to the Authentik authorize endpoint.
``GET /auth/callback``  -> exchanges the code, verifies the ID token,
                           provisions the local user, sets the session cookie
                           (httpOnly / SameSite=Lax / Secure per _secure_cookie)
                           and 302s to "/".
``GET /auth/logout``    -> revokes the session token, clears the cookie,
                           302s back to /auth/login.

Impersonation
-------------
``POST /api/admin/impersonate``       {username}  - real admin only
``POST /api/admin/impersonate/stop``                    - real admin only
``GET  /api/admin/users``                          - real admin only

"Real admin" is resolved from the session cookie directly, NOT from
request.state.current_user, because AuthMiddleware has already swapped
current_user to the impersonation target for the current request. Every
impersonation start/stop is written to data/admin_audit.log.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional, Tuple

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

from core import sso
from core.auth import TOKEN_TTL
from core.isolation import audit
from routes.auth_routes import SESSION_COOKIE, _secure_cookie
from src.owner_identity import RESERVED_AUTH_USERNAMES

logger = logging.getLogger(__name__)


class ImpersonateRequest(BaseModel):
    username: str


def setup_sso_routes(auth_manager) -> APIRouter:
    router = APIRouter(tags=["sso"])

    def _set_session_cookie(response: Response, request: Request, token: str) -> None:
        response.set_cookie(
            key=SESSION_COOKIE,
            value=token,
            httponly=True,
            samesite="lax",
            secure=_secure_cookie(request),
            path="/",
            max_age=TOKEN_TTL,
        )

    def _real_user(request: Request) -> Tuple[Optional[str], Optional[str]]:
        """(username, token) of the account that OWNS the session cookie —
        never the impersonation target."""
        token = request.cookies.get(SESSION_COOKIE)
        if not token:
            return None, None
        return auth_manager.get_username_for_token(token), token

    def _require_real_admin(request: Request) -> Tuple[str, str]:
        real, token = _real_user(request)
        if not real or not token:
            raise HTTPException(401, "Not authenticated")
        if not auth_manager.is_admin(real):
            raise HTTPException(403, "Admin only")
        return real, token

    # ------------------------------------------------------------------
    # SSO flow
    # ------------------------------------------------------------------

    @router.get("/auth/login")
    async def sso_login(request: Request):
        if not sso.sso_enabled():
            raise HTTPException(404, "Not found")
        try:
            state, nonce, verifier = sso.create_login_session()
            url = await asyncio.to_thread(sso.build_authorization_url, state, nonce, verifier)
        except sso.SSOError as e:
            logger.warning("SSO login setup failed: %s", e)
            return JSONResponse(
                status_code=502,
                content={"error": "Could not start sign-in. Please try again."},
            )
        return RedirectResponse(url=url, status_code=302)

    @router.get("/auth/callback")
    async def sso_callback(request: Request):
        if not sso.sso_enabled():
            raise HTTPException(404, "Not found")
        error = request.query_params.get("error")
        if error:
            desc = request.query_params.get("error_description", "")
            return JSONResponse(
                status_code=400,
                content={"error": f"Sign-in failed: {desc or error}"},
            )
        code = request.query_params.get("code", "")
        state = request.query_params.get("state", "")
        if not code:
            return JSONResponse(status_code=400, content={"error": "Missing authorization code"})
        try:
            username, token = await asyncio.to_thread(
                sso.complete_sso_login, auth_manager, code, state
            )
        except sso.SSOError as e:
            logger.warning("SSO callback failed: %s", e)
            return JSONResponse(status_code=400, content={"error": str(e)})
        response = RedirectResponse(url="/", status_code=302)
        _set_session_cookie(response, request, token)
        audit("sso_login", request, actor=username)
        return response

    @router.get("/auth/logout")
    async def sso_logout(request: Request, response: Response):
        token = request.cookies.get(SESSION_COOKIE)
        if token:
            audit("sso_logout", request)
            auth_manager.revoke_token(token)
        response.delete_cookie(SESSION_COOKIE, path="/")
        return RedirectResponse(url="/auth/login", status_code=302)

    # ------------------------------------------------------------------
    # Admin impersonation
    # ------------------------------------------------------------------

    @router.post("/api/admin/impersonate")
    async def impersonate(body: ImpersonateRequest, request: Request):
        real, token = _require_real_admin(request)
        target = (body.username or "").strip().lower()
        if not target:
            raise HTTPException(400, "username is required")
        if target in RESERVED_AUTH_USERNAMES:
            raise HTTPException(400, "username is reserved")
        if target not in auth_manager.users:
            raise HTTPException(404, "User not found")
        if target == real:
            # "Viewing as yourself" means stop impersonating.
            auth_manager.clear_impersonating(token)
            audit("impersonation_stop", request, actor=real, target=target)
            return {"ok": True, "impersonating": None}
        if not auth_manager.set_impersonating(token, target):
            raise HTTPException(500, "Could not start impersonation")
        audit("impersonation_start", request, actor=real, target=target)
        return {"ok": True, "impersonating": target}

    @router.post("/api/admin/impersonate/stop")
    async def impersonate_stop(request: Request):
        real, token = _require_real_admin(request)
        target = (auth_manager.get_session(token) or {}).get("impersonating")
        auth_manager.clear_impersonating(token)
        audit("impersonation_stop", request, actor=real, target=target)
        return {"ok": True, "impersonating": None}

    @router.get("/api/admin/users")
    async def admin_users(request: Request):
        real, _ = _require_real_admin(request)
        users = []
        for name, info in auth_manager.users.items():
            sso_meta = info.get("sso") or {}
            users.append({
                "username": name,
                "is_admin": bool(info.get("is_admin")),
                "sso_groups": list(sso_meta.get("groups") or []),
                "last_sso": sso_meta.get("last_sso"),
            })
        users.sort(key=lambda u: u["username"])
        return {"users": users, "real_admin": real}

    return router
