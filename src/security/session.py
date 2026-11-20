import hashlib
import secrets
from dataclasses import dataclass

ROLES = {"junior_analyst", "senior_investigator", "compliance_officer"}


@dataclass
class Session:
    session_token: str
    sub: str           # unique user subject ID e.g. 'junior_alice'
    actor_role: str    # one of ROLES
    tenant_id: str


class SessionRegistry:
    _sessions: dict  # class-level dict: token -> Session

    @classmethod
    def _init(cls):
        if not hasattr(cls, '_sessions'):
            cls._sessions = {}

    @classmethod
    def create(cls, sub: str, actor_role: str, tenant_id: str, token: str | None = None) -> str:
        """Generate token = 'tok_' + secrets.token_hex(16) (or use specified token), store Session, return token."""
        if actor_role not in ROLES:
            raise ValueError(f"Invalid actor_role: '{actor_role}'. Must be one of {ROLES}")
        cls._init()
        if token is None:
            token = "tok_" + secrets.token_hex(16)
        cls._sessions[token] = Session(
            session_token=token, sub=sub, actor_role=actor_role, tenant_id=tenant_id
        )
        return token

    @classmethod
    def resolve(cls, session_token: str) -> Session:
        """Return Session or raise ValueError('INVALID_SESSION_TOKEN')."""
        cls._init()
        session = cls._sessions.get(session_token)
        if session is None:
            raise ValueError("INVALID_SESSION_TOKEN")
        return session

    @classmethod
    def revoke(cls, session_token: str) -> None:
        cls._init()
        cls._sessions.pop(session_token, None)


# Pre-seed 6 demo sessions at module import time
# Store tokens in DEMO_TOKENS dict: sub -> token
DEMO_TOKENS: dict[str, str] = {}


def _seed_demo_sessions():
    demos = [
        ("junior_alice",  "junior_analyst",      "tenant_neobank_in"),
        ("junior_bob",    "junior_analyst",       "tenant_b2b_cards"),
        ("senior_carol",  "senior_investigator",  "tenant_neobank_in"),
        ("senior_dave",   "senior_investigator",  "tenant_b2b_cards"),
        ("officer_eve",   "compliance_officer",   "tenant_neobank_in"),
        ("officer_frank", "compliance_officer",   "tenant_b2b_cards"),
    ]
    for sub, role, tenant in demos:
        # Deterministic token derived from sub so external MCP clients can reliably authenticate
        token_hash = hashlib.sha256(f"demo_session:{sub}".encode("utf-8")).hexdigest()[:16]
        token = f"tok_demo_{sub}_{token_hash}"
        token = SessionRegistry.create(sub, role, tenant, token=token)
        DEMO_TOKENS[sub] = token


_seed_demo_sessions()
