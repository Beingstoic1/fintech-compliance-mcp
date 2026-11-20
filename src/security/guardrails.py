import re
import hashlib
import json
import unicodedata
from typing import Any

from src.security.session import SessionRegistry, Session

# Zero-width and invisible Unicode characters to strip before injection check
_INVISIBLE_RE = re.compile(
    r'[\u200b\u200c\u200d\u200e\u200f\u00ad\u2060\u2061\u2062\u2063\u2064\ufeff\u180e]'
)

# Common Cyrillic/Greek → Latin homoglyph confusables map
_CONFUSABLES: dict[str, str] = {
    # Cyrillic uppercase
    '\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u041d': 'H',
    '\u041a': 'K', '\u041c': 'M', '\u041e': 'O', '\u0420': 'P', '\u0422': 'T',
    '\u0425': 'X', '\u0423': 'Y', '\u0405': 'S',
    # Cyrillic lowercase
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0443': 'y', '\u0445': 'x', '\u0455': 's',
    # Greek
    '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0396': 'Z', '\u0397': 'H',
    '\u0399': 'I', '\u039a': 'K', '\u039c': 'M', '\u039d': 'N', '\u039f': 'O',
    '\u03a1': 'P', '\u03a4': 'T', '\u03a5': 'Y', '\u03a7': 'X',
    '\u03b1': 'a', '\u03b5': 'e', '\u03bf': 'o', '\u03c1': 'p',
}

# PII masking regexes
ACCOUNT_NUMBER_RE = re.compile(r'\b(\d{8,16})\b')
PAN_RE = re.compile(r'\b([A-Z]{5}\d{4}[A-Z])\b')       # e.g. ABCDE1234F
TAX_ID_RE = re.compile(r'\b([A-Z]{2}-\d{7})\b')         # e.g. AB-1234567
INJECTION_RE = re.compile(
    r'(?i)(IGNORE\s*PREVIOUS\s*INSTRUCTIONS?|SYSTEM\s*PROMPT|JAILBREAK|'
    r'DISREGARD\s*ALL|FORGET\s*(YOUR\s*)?INSTRUCTIONS?|'
    r'DO\s*NOT\s*FOLLOW|OVERRIDE\s*(PREVIOUS\s*)?INSTRUCTIONS?)',
    re.IGNORECASE
)

RBAC_MATRIX: dict[str, set[str]] = {
    "get_account_profile":           {"junior_analyst", "senior_investigator", "compliance_officer"},
    "query_transactions":            {"junior_analyst", "senior_investigator", "compliance_officer"},
    "detect_structuring_anomalies":  {"junior_analyst", "senior_investigator", "compliance_officer"},
    "request_account_freeze":        {"senior_investigator"},
    "request_fee_refund":            {"senior_investigator"},
    "execute_approved_action":       {"compliance_officer"},
}


def canonical_json(args_dict: dict) -> str:
    """json.dumps(sort_keys=True, separators=(',',':'), ensure_ascii=True)"""
    return json.dumps(args_dict, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def compute_args_sha256(tool_name: str, args_dict: dict, requester_sub: str) -> str:
    """SHA256(tool_name + '|' + canonical_json(args_dict) + '|' + requester_sub)"""
    payload = tool_name + "|" + canonical_json(args_dict) + "|" + requester_sub
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def pre_check(session_token: str, tool_name: str, args: dict) -> Session:
    """
    1. Resolve session via SessionRegistry.resolve() — raises ValueError on bad token
    2. Lookup RBAC_MATRIX.get(tool_name, set()) — if role not in allowed_roles:
       raise PermissionError(f"RBAC_BLOCK: role '{session.actor_role}' cannot call '{tool_name}'")
    3. Return session
    """
    session = SessionRegistry.resolve(session_token)
    allowed_roles = RBAC_MATRIX.get(tool_name, set())
    if session.actor_role not in allowed_roles:
        raise PermissionError(
            f"RBAC_BLOCK: role '{session.actor_role}' cannot call '{tool_name}'"
        )
    return session


def _mask_string(value: str, session: Session) -> str:
    """
    For ALL roles: strip injection patterns → '[INJECTION STRIPPED]'
    Uses Unicode normalization (NFKD → ASCII fold + confusables) to defeat
    homoglyph/ZWSP evasion.
    For junior_analyst ONLY additionally:
      - Account numbers (8-16 digits): replace with '****' + last4
      - PAN 'ABCDE1234F' → 'XXXXX' + last4 chars of match (e.g. '234F')
      - Tax ID 'AB-1234567' → 'XX-XXX' + last4 chars (e.g. '4567')
    """
    # --- Injection detection (all roles) ---
    # 1. Strip zero-width / invisible characters
    normalized = _INVISIBLE_RE.sub('', value)
    # 2. NFKD normalize + drop combining marks
    normalized = unicodedata.normalize('NFKD', normalized)
    normalized = ''.join(
        ch for ch in normalized if not unicodedata.combining(ch)
    )
    # 3. Apply confusables map (Cyrillic/Greek → Latin)
    # Check both phonetic (С -> S) and visual (С -> C) substitutions
    norm_s = ''.join({'\u0421': 'S', '\u0441': 's'}.get(ch, _CONFUSABLES.get(ch, ch)) for ch in normalized)
    norm_c = ''.join({'\u0421': 'C', '\u0441': 'c'}.get(ch, _CONFUSABLES.get(ch, ch)) for ch in normalized)

    # Check normalized variants and original form for injection
    if INJECTION_RE.search(norm_s):
        result = INJECTION_RE.sub('[INJECTION STRIPPED]', norm_s)
    elif INJECTION_RE.search(norm_c):
        result = INJECTION_RE.sub('[INJECTION STRIPPED]', norm_c)
    elif INJECTION_RE.search(value):
        result = INJECTION_RE.sub('[INJECTION STRIPPED]', value)
    else:
        result = value

    if session.actor_role == "junior_analyst":
        # Mask account numbers
        def mask_account(m):
            full = m.group(1)
            return '****' + full[-4:]
        result = ACCOUNT_NUMBER_RE.sub(mask_account, result)

        # Mask PAN
        def mask_pan(m):
            full = m.group(1)
            return 'XXXXX' + full[-4:]
        result = PAN_RE.sub(mask_pan, result)

        # Mask tax ID
        def mask_tax(m):
            full = m.group(1)
            return 'XX-XXX' + full[-4:]
        result = TAX_ID_RE.sub(mask_tax, result)

    return result


def _sanitize_value(value: Any, session: Session) -> tuple[Any, bool]:
    """Recursively sanitize a value. Return (sanitized, was_modified)."""
    if isinstance(value, str):
        masked = _mask_string(value, session)
        return masked, masked != value
    elif isinstance(value, dict):
        return sanitize_record(value, session)
    elif isinstance(value, list):
        new_list = []
        modified = False
        for item in value:
            new_item, m = _sanitize_value(item, session)
            new_list.append(new_item)
            modified = modified or m
        return new_list, modified
    return value, False


def sanitize_record(record: dict, session: Session) -> tuple[dict, bool]:
    """Walk every value in record, apply _sanitize_value. Return (sanitized_record, was_modified)."""
    new_record = {}
    modified = False
    for k, v in record.items():
        new_v, m = _sanitize_value(v, session)
        new_record[k] = new_v
        modified = modified or m
    return new_record, modified


def sanitize_list(records: list[dict], session: Session) -> tuple[list[dict], bool]:
    new_list = []
    any_modified = False
    for record in records:
        new_rec, m = sanitize_record(record, session)
        new_list.append(new_rec)
        any_modified = any_modified or m
    return new_list, any_modified


def post_process(result: Any, session: Session, tool_name: str, args_sha256: str) -> dict:
    """
    Sanitize result. If result is a list, use sanitize_list; if dict, use sanitize_record.
    Return:
    {
        "data": sanitized_result,
        "decision": "REDACT" if modified else "ALLOW",
        "session_sub": session.sub,
        "actor_role": session.actor_role,
        "tenant_id": session.tenant_id,
        "args_sha256": args_sha256
    }
    """
    if isinstance(result, list):
        sanitized, modified = sanitize_list(result, session)
    elif isinstance(result, dict):
        sanitized, modified = sanitize_record(result, session)
    else:
        sanitized = result
        modified = False

    return {
        "data": sanitized,
        "decision": "REDACT" if modified else "ALLOW",
        "session_sub": session.sub,
        "actor_role": session.actor_role,
        "tenant_id": session.tenant_id,
        "args_sha256": args_sha256,
    }
