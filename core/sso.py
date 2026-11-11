"""Authentik OIDC (OpenID Connect) single sign-on for Odysseus.

Implements the authorization-code flow with PKCE (S256) against the
"odysseus" OAuth2 application on the local Authentik instance:

  issuer:      https://12390.vr2.in/application/o/odysseus/
  redirect:    https://12353.vr2.in/auth/callback   (strict match on the provider)
  scopes:      openid profile email groups
  signing:     RS256 via the provider's JWKS (default self-signed keypair)

Configuration comes from .env (see ODYSSEUS_ISOLATION_NOTES.md §9):
  SSO_ENABLED, SSO_ISSUER, SSO_CLIENT_ID, SSO_CLIENT_SECRET,
  SSO_ADMIN_GROUP, SSO_USER_GROUPS, SSO_ADMIN_EMAIL, SSO_SESSION_SECRET.

Security notes
--------------
* ``state`` and ``nonce`` are one-time, short-TTL, server-side values in an
  opaque random store (never derived from client input).
* The ID token is verified against the issuer's JWKS: RS256 signature,
  ``iss`` (exact), ``aud`` (contains client id), ``exp``/``nbf`` (with a small
  clock skew) and ``nonce`` (replay protection).
* Local username = verified email, lowercased. This matches the existing
  local account names, so legacy data stays owned by the same users.
* Role: admin iff the token's ``groups`` contain SSO_ADMIN_GROUP or the email
  equals SSO_ADMIN_EMAIL (hard fallback so su1@vr2.in can never be locked out
  of admin even if the group claim were ever misconfigured).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlencode

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

logger = logging.getLogger(__name__)

STATE_TTL = 300            # seconds a /auth/login state entry stays valid
CLOCK_SKEW = 30            # seconds of leeway for exp/nbf
DISCOVERY_TTL = 3600       # cache the .well-known document for an hour
JWKS_TTL = 3600
HTTP_TIMEOUT = 15


class SSOError(Exception):
    """SSO flow failure with a message safe to show to the user."""


def sso_enabled() -> bool:
    return os.getenv("SSO_ENABLED", "false").strip().lower() == "true"


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


@dataclass
class _Config:
    issuer: str
    client_id: str
    client_secret: str
    admin_group: str
    user_groups: Tuple[str, ...]
    admin_email: str
    session_secret: str


_config: Optional[_Config] = None
_config_lock = threading.Lock()


def _get_config() -> _Config:
    global _config
    with _config_lock:
        if _config is None:
            # Keep the issuer verbatim (including a trailing slash):
            # authentik's per-provider issuer is ".../application/o/<slug>/"
            # and both the discovery document and the ID token's `iss` claim
            # carry it exactly that way. Trailing-slash stripping here used
            # to make the exact-match checks fail on every request.
            issuer = _env("SSO_ISSUER")
            client_id = _env("SSO_CLIENT_ID")
            client_secret = _env("SSO_CLIENT_SECRET")
            session_secret = _env("SSO_SESSION_SECRET")
            if not (issuer and client_id and client_secret and session_secret):
                raise SSOError("SSO is enabled but SSO_* environment configuration is incomplete")
            _config = _Config(
                issuer=issuer,
                client_id=client_id,
                client_secret=client_secret,
                admin_group=_env("SSO_ADMIN_GROUP", "odysseus-admins"),
                user_groups=tuple(g.strip() for g in _env("SSO_USER_GROUPS", "odysseus-admins,odysseus-users").split(",") if g.strip()),
                admin_email=_env("SSO_ADMIN_EMAIL", "su1@vr2.in").lower(),
                session_secret=session_secret,
            )
        return _config


def redirect_uri() -> str:
    """Absolute callback URL. The provider has ONE strict redirect URI, so this
    must match it byte-for-byte; derive it from the issuer host's app port
    rather than trusting the incoming request (the tunnel always presents the
    public https URL)."""
    return os.getenv("SSO_REDIRECT_URI", "").strip() or "https://12353.vr2.in/auth/callback"


# ---------------------------------------------------------------------------
# Discovery + JWKS (cached)
# ---------------------------------------------------------------------------

_discovery: Dict[str, Any] = {}
_discovery_at = 0.0
_jwks: Dict[str, Dict[str, Any]] = {}
_jwks_at = 0.0
_cache_lock = threading.Lock()


def _http_json(method: str, url: str, **kwargs) -> Any:
    try:
        resp = requests.request(method, url, timeout=HTTP_TIMEOUT, **kwargs)
    except requests.RequestException as e:
        raise SSOError(f"Cannot reach identity provider: {e.__class__.__name__}") from e
    if resp.status_code >= 400:
        raise SSOError(f"Identity provider returned HTTP {resp.status_code}")
    try:
        return resp.json()
    except ValueError as e:
        raise SSOError("Identity provider returned invalid JSON") from e


def discovery() -> Dict[str, Any]:
    cfg = _get_config()
    global _discovery, _discovery_at
    with _cache_lock:
        if _discovery and time.time() - _discovery_at < DISCOVERY_TTL:
            return _discovery
    doc = _http_json("GET", f"{cfg.issuer.rstrip('/')}/.well-known/openid-configuration")
    if doc.get("issuer") != cfg.issuer:
        raise SSOError("Issuer mismatch on discovery document")
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not doc.get(key):
            raise SSOError(f"Discovery document missing {key}")
    with _cache_lock:
        _discovery, _discovery_at = doc, time.time()
    return doc


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _jwk_to_public_key(jwk: Dict[str, Any]) -> rsa.RSAPublicKey:
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    from cryptography.hazmat.primitives.serialization import load_der_public_key  # noqa: F401

    n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
    numbers = RSAPublicNumbers(e, n)
    return numbers.public_key()


def jwks(force_refresh: bool = False) -> Dict[str, Dict[str, Any]]:
    """kid -> JWK. Refreshed once when an unknown kid is requested (key rotation)."""
    global _jwks, _jwks_at
    with _cache_lock:
        fresh = _jwks and (time.time() - _jwks_at < JWKS_TTL) and not force_refresh
        if fresh:
            return _jwks
    doc = discovery()
    raw = _http_json("GET", doc["jwks_uri"])
    keys = {}
    for jwk in raw.get("keys", []):
        if jwk.get("kty") == "RSA" and jwk.get("kid"):
            keys[jwk["kid"]] = jwk
    if not keys:
        raise SSOError("No RSA keys in JWKS")
    with _cache_lock:
        _jwks, _jwks_at = keys, time.time()
    return keys


# ---------------------------------------------------------------------------
# state / nonce / PKCE store
# ---------------------------------------------------------------------------

_state_store: Dict[str, Dict[str, Any]] = {}
_state_lock = threading.Lock()


def _prune_states() -> None:
    now = time.time()
    for token in [t for t, e in _state_store.items() if now - e["created_at"] > STATE_TTL]:
        _state_store.pop(token, None)


def create_login_session() -> Tuple[str, str, str]:
    """Return (state, nonce, code_verifier) for a new /auth/login redirect."""
    _prune_states()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(48)
    with _state_lock:
        _state_store[state] = {
            "nonce": nonce,
            "code_verifier": verifier,
            "created_at": time.time(),
        }
    return state, nonce, verifier


def consume_login_session(state: Optional[str]) -> Optional[Dict[str, Any]]:
    """Single-use pop of the state entry. None when unknown/expired/replayed."""
    if not state:
        return None
    with _state_lock:
        entry = _state_store.pop(state, None)
        if entry is not None and time.time() - entry["created_at"] > STATE_TTL:
            return None
        return entry


def build_authorization_url(state: str, nonce: str, code_verifier: str) -> str:
    cfg = _get_config()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    doc = discovery()
    params = {
        "response_type": "code",
        "client_id": cfg.client_id,
        "redirect_uri": redirect_uri(),
        "scope": "openid profile email groups",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "prompt": "select_account",
    }
    return f"{doc['authorization_endpoint']}?{urlencode(params)}"


# ---------------------------------------------------------------------------
# Code exchange + ID-token verification
# ---------------------------------------------------------------------------

def exchange_code(code: str, code_verifier: str) -> Dict[str, Any]:
    cfg = _get_config()
    doc = discovery()
    body = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri(),
        "client_id": cfg.client_id,
        "client_secret": cfg.client_secret,
        "code_verifier": code_verifier,
    }
    data = _http_json("POST", doc["token_endpoint"], data=body)
    if "id_token" not in data:
        raise SSOError("Token response missing id_token")
    return data


def _decode_jwt_unverified(token: str) -> Tuple[Dict[str, Any], bytes, str]:
    """Return (header, signing_input, signature) without verifying."""
    parts = token.split(".")
    if len(parts) != 3:
        raise SSOError("Malformed ID token")
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except (ValueError, TypeError) as e:
        raise SSOError("Malformed ID token header") from e
    return header, f"{parts[0]}.{parts[1]}".encode("ascii"), _b64url_decode(parts[2])


def verify_id_token(id_token: str, expected_nonce: str) -> Dict[str, Any]:
    """Verify signature + standard claims. Returns the claims dict."""
    cfg = _get_config()
    header, signing_input, signature = _decode_jwt_unverified(id_token)
    if header.get("alg") != "RS256":
        raise SSOError(f"Unsupported token algorithm {header.get('alg')!r}")
    kid = header.get("kid")
    keys = jwks()
    jwk = keys.get(kid)
    if jwk is None:
        # Key rotation: retry once with a forced refresh before failing.
        keys = jwks(force_refresh=True)
        jwk = keys.get(kid)
    if jwk is None:
        raise SSOError("Token signing key not found in JWKS")
    public_key = _jwk_to_public_key(jwk)
    try:
        public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as e:
        raise SSOError("ID token signature verification failed") from e

    try:
        claims = json.loads(_b64url_decode(id_token.split(".")[1]))
    except (ValueError, TypeError) as e:
        raise SSOError("Malformed ID token claims") from e

    if claims.get("iss") != cfg.issuer:
        raise SSOError("ID token issuer mismatch")
    aud = claims.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    if cfg.client_id not in auds:
        raise SSOError("ID token audience mismatch")
    now = time.time()
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or exp + CLOCK_SKEW < now:
        raise SSOError("ID token expired")
    nbf = claims.get("nbf")
    if isinstance(nbf, (int, float)) and nbf - CLOCK_SKEW > now:
        raise SSOError("ID token not yet valid")
    if not hmac.compare_digest(str(claims.get("nonce", "")), expected_nonce):
        raise SSOError("ID token nonce mismatch")
    if not claims.get("sub"):
        raise SSOError("ID token missing sub")
    return claims


# ---------------------------------------------------------------------------
# Identity -> local user
# ---------------------------------------------------------------------------

def _sanitize_username_fallback(sub: str) -> str:
    """Last-resort username when no usable email is present: a stable slug
    derived from sub so the same person always maps to the same account."""
    digest = hashlib.sha256(sub.encode("utf-8")).hexdigest()[:8]
    return f"user-{digest}"


def identity_from_claims(claims: Dict[str, Any]) -> Dict[str, Any]:
    """Map verified ID-token claims to local identity + role.

    Access control is the Authentik application policy's job (odysseus-access
    allows any active authentik user as of 2026-11-11); this function only
    maps the verified claims and derives the local role. Admin iff the
    ``groups`` claim contains SSO_ADMIN_GROUP or the email equals
    SSO_ADMIN_EMAIL. Missing/malformed ``groups`` simply means non-admin.
    """
    cfg = _get_config()
    email = str(claims.get("email") or "").strip().lower()
    if "@" not in email or "." not in email.split("@", 1)[-1]:
        # Fall back to preferred_username only when it looks like an address
        # (local accounts are email-named); otherwise stable sub slug.
        pref = str(claims.get("preferred_username") or "").strip().lower()
        email = pref if ("@" in pref) else _sanitize_username_fallback(str(claims.get("sub")))
    groups = claims.get("groups")
    groups = [str(g).lower() for g in groups] if isinstance(groups, list) else []
    is_admin = (cfg.admin_group in groups) or (email == cfg.admin_email)
    return {
        "username": email,
        "email": email,
        "sub": str(claims.get("sub")),
        "groups": groups,
        "is_admin": is_admin,
        "display_name": claims.get("name") or claims.get("preferred_username") or email,
    }


def provision_local_user(auth_manager, identity: Dict[str, Any]) -> str:
    """Create/update the local user for an SSO identity. Returns username.

    The role is recomputed on every login so group changes in Authentik take
    effect without touching auth.json by hand.
    """
    username = identity["username"]
    if username not in auth_manager.users:
        # Random unusable password: password login is disabled in SSO mode
        # anyway, and create_user needs a hash to store.
        password = secrets.token_urlsafe(32)
        if not auth_manager.create_user(username, password, is_admin=identity["is_admin"]):
            raise SSOError(f"Could not provision local user '{username}'")
    auth_manager.update_sso_metadata(
        username,
        sub=identity["sub"],
        email=identity["email"],
        groups=identity["groups"],
        is_admin=identity["is_admin"],
    )
    # Ensure the per-user agent workspace exists (0700, owner-only) so the
    # first agent turn never races a late mkdir (workspace isolation G1).
    try:
        from src.tool_execution import provision_user_workspace

        provision_user_workspace(username)
    except Exception:
        logger.warning("Could not provision agent workspace for SSO user %r", username, exc_info=True)
    return username


def complete_sso_login(auth_manager, code: str, state: str) -> Tuple[str, str]:
    """Full callback pipeline: state -> code exchange -> token verify ->
    provision. Returns (username, session_token)."""
    entry = consume_login_session(state)
    if entry is None:
        raise SSOError("Login session expired or invalid — please sign in again")
    token_data = exchange_code(code, entry["code_verifier"])
    claims = verify_id_token(token_data["id_token"], entry["nonce"])
    identity = identity_from_claims(claims)
    username = provision_local_user(auth_manager, identity)
    session_token = auth_manager.create_session_trusted(username)
    if not session_token:
        raise SSOError("Could not create local session")
    logger.info("SSO login complete for '%s' (admin=%s)", username, identity["is_admin"])
    return username, session_token
