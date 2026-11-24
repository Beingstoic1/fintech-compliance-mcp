"""Dev user directory for the local dev issuer.

There is no token registry here any more (T04). Identity is a signed JWT verified
by ``src.security.identity``; this module only lists the demo users the dev issuer
may mint tokens for. It holds no secrets and no derivable credentials.
"""
from src.domain.policy import ROLES

# sub -> (role, tenant_id)
DEMO_DIRECTORY: dict[str, tuple[str, str]] = {
    "junior_alice":  ("junior_analyst",      "tenant_neobank_in"),
    "junior_bob":    ("junior_analyst",      "tenant_b2b_cards"),
    "senior_carol":  ("senior_investigator", "tenant_neobank_in"),
    "senior_dave":   ("senior_investigator", "tenant_b2b_cards"),
    "officer_eve":   ("compliance_officer",  "tenant_neobank_in"),
    "officer_frank": ("compliance_officer",  "tenant_b2b_cards"),
}

assert all(role in ROLES for role, _ in DEMO_DIRECTORY.values())
