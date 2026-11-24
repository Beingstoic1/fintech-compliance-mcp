"""Transport-bound identity (T04).

The caller's identity is a signed JWT verified here, never a tool argument.

Sources of the bearer token, in order:
  1. Streamable-HTTP: the MCP SDK's bearer middleware calls ``JWTTokenVerifier``
     and stores the AccessToken in its auth context.
  2. In-process adapters (Workbench, tests): ``authenticated(token)`` verifies the
     JWT with the same code and binds it to the same auth context.
  3. stdio: the operator sets ``FINTECH_STDIO_BEARER_TOKEN`` at process launch
     (out of band, never visible to the model); it is re-verified on every call.

Keys: ``FINTECH_JWT_SECRET`` (HS256, >= 32 bytes) or ``FINTECH_JWT_PUBLIC_KEY``
(PEM, RS256/ES256 via ``FINTECH_JWT_ALGORITHM``). With neither set, an ephemeral
per-process HS256 key is generated: in-process dev callers can mint tokens, but no
token from outside the process can ever verify.
"""
from __future__ import annotations

import contextlib
import os
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterator, TypeVar

import jwt

from src.domain.policy import ROLES

from mcp.server.auth.middleware.auth_context import auth_context_var, get_access_token
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken

T = TypeVar("T")

ISSUER = os.environ.get("FINTECH_JWT_ISSUER", "http://localhost:8000")
AUDIENCE = os.environ.get("FINTECH_JWT_AUDIENCE", "fintech-compliance-mcp")
MAX_TOKEN_LIFETIME_S = 3600
CLOCK_LEEWAY_S = 30
_TENANT_RE = re.compile(r"^tenant_[a-z0-9_]{1,48}$")
_SUB_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
_ALLOWED_ALGS = {"HS256", "RS256", "ES256"}


class AuthenticationError(ValueError):
    """Raised for any missing/invalid credential. Message is a safe, generic code."""


@dataclass(frozen=True)
class Principal:
    sub: str
    role: str
    tenant_id: str
    issuer: str
    amr: tuple[str, ...] = ()
    expires_at: int | None = None

    @property
    def actor_role(self) -> str:  # audit-column naming
        return self.role


# ─── key material ────────────────────────────────────────────────────────────

def _load_keys() -> tuple[str, Any, Any]:
    """Return (algorithm, signing_key_or_None, verification_key)."""
    alg = os.environ.get("FINTECH_JWT_ALGORITHM", "HS256").upper()
    if alg not in _ALLOWED_ALGS:
        raise RuntimeError(f"FINTECH_JWT_ALGORITHM must be one of {sorted(_ALLOWED_ALGS)}")
    if alg == "HS256":
        secret = os.environ.get("FINTECH_JWT_SECRET")
        if secret is None:
            secret = secrets.token_urlsafe(48)  # ephemeral: unforgeable outside this process
        if len(secret.encode()) < 32:
            raise RuntimeError("FINTECH_JWT_SECRET must be at least 32 bytes")
        return alg, secret, secret
    pub = os.environ.get("FINTECH_JWT_PUBLIC_KEY")
    if not pub:
        raise RuntimeError(f"{alg} requires FINTECH_JWT_PUBLIC_KEY (PEM)")
    return alg, os.environ.get("FINTECH_JWT_PRIVATE_KEY"), pub


_ALG, _SIGNING_KEY, _VERIFY_KEY = _load_keys()


# ─── verification ────────────────────────────────────────────────────────────

def verify_jwt(token: str) -> Principal:
    """Verify signature, iss, aud, exp, nbf, iat, lifetime, and identity claims."""
    if not isinstance(token, str) or not token or len(token) > 8192:
        raise AuthenticationError("UNAUTHENTICATED")
    try:
        claims = jwt.decode(
            token,
            _VERIFY_KEY,
            algorithms=[_ALG],  # pinned; never "none", never alg-confusion
            audience=AUDIENCE,
            issuer=ISSUER,
            leeway=CLOCK_LEEWAY_S,
            options={"require": ["exp", "iat", "nbf", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError:
        raise AuthenticationError("UNAUTHENTICATED") from None

    if claims["exp"] - claims["iat"] > MAX_TOKEN_LIFETIME_S:
        raise AuthenticationError("UNAUTHENTICATED")
    sub, role, tenant = claims.get("sub"), claims.get("role"), claims.get("tenant_id")
    if not (isinstance(sub, str) and _SUB_RE.match(sub)):
        raise AuthenticationError("UNAUTHENTICATED")
    if role not in ROLES:
        raise AuthenticationError("UNAUTHENTICATED")
    if not (isinstance(tenant, str) and _TENANT_RE.match(tenant)):
        raise AuthenticationError("UNAUTHENTICATED")
    amr = claims.get("amr") or []
    return Principal(
        sub=sub, role=role, tenant_id=tenant, issuer=claims["iss"],
        amr=tuple(a for a in amr if isinstance(a, str)), expires_at=int(claims["exp"]),
    )


def _access_token(token: str, p: Principal) -> AccessToken:
    return AccessToken(
        token=token, client_id=p.sub, scopes=[p.role], expires_at=p.expires_at,
        resource=AUDIENCE, subject=p.sub,
        claims={"iss": p.issuer, "role": p.role, "tenant_id": p.tenant_id, "amr": list(p.amr)},
    )


class JWTTokenVerifier:
    """mcp ``TokenVerifier`` for the Streamable-HTTP bearer middleware."""

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            return _access_token(token, verify_jwt(token))
        except AuthenticationError:
            return None


# ─── resolving the current caller ────────────────────────────────────────────

def current_principal() -> Principal:
    """The verified caller for this request. Raises AuthenticationError if none."""
    at = get_access_token()
    if at is not None:
        # Re-verify: the context value is only ever set from a verified token, but
        # re-checking keeps expiry enforcement exact for long-lived connections.
        return verify_jwt(at.token)
    if _STDIO_MODE:
        stdio_token = os.environ.get("FINTECH_STDIO_BEARER_TOKEN")
        if stdio_token:
            return verify_jwt(stdio_token)
    raise AuthenticationError("UNAUTHENTICATED")


_STDIO_MODE = False


def enable_stdio_identity() -> None:
    """Called only by the stdio entrypoint. HTTP mode never falls back to the env token."""
    global _STDIO_MODE
    _STDIO_MODE = True


@contextlib.contextmanager
def authenticated(token: str) -> Iterator[Principal]:
    """Bind a verified bearer token to the current context (in-process adapters)."""
    p = verify_jwt(token)
    reset = auth_context_var.set(AuthenticatedUser(_access_token(token, p)))
    try:
        yield p
    finally:
        auth_context_var.reset(reset)


def call_as(token: str, fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    with authenticated(token):
        return fn(*args, **kwargs)


# ─── dev issuer ──────────────────────────────────────────────────────────────

def issue_dev_token(
    sub: str, role: str, tenant_id: str, *, ttl_s: int = 900, amr: tuple[str, ...] = ("pwd",),
) -> str:
    """Mint a short-lived token signed with this process's key (dev/test only)."""
    if _SIGNING_KEY is None:
        raise RuntimeError("No signing key configured; tokens must come from the real IdP")
    if role not in ROLES:
        raise ValueError(f"Invalid role: {role!r}")
    if not 0 < ttl_s <= MAX_TOKEN_LIFETIME_S:
        raise ValueError("ttl_s out of range")
    now = int(time.time())
    claims = {
        "iss": ISSUER, "aud": AUDIENCE, "sub": sub, "role": role, "tenant_id": tenant_id,
        "amr": list(amr), "iat": now, "nbf": now, "exp": now + ttl_s,
        "jti": secrets.token_hex(8),
    }
    return jwt.encode(claims, _SIGNING_KEY, algorithm=_ALG)


def issue_demo_token(sub: str, **kw: Any) -> str:
    from src.security.session import DEMO_DIRECTORY
    role, tenant = DEMO_DIRECTORY[sub]
    return issue_dev_token(sub, role, tenant, **kw)
