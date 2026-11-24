"""HMAC keyrings with key ids (rotation-ready).

Each keyring loads ``"kid1:secret1,kid2:secret2"`` from an env var plus an
active-kid env var. Without them, a dev keyring is created once in a 0600 file
next to the DB, so separate processes sharing that DB (MCP server, Workbench)
agree on keys. Production must supply keys via env / a secrets manager.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path

_MIN_SECRET_BYTES = 32


def _parse(spec: str, env: str) -> dict[str, bytes]:
    keys: dict[str, bytes] = {}
    for part in filter(None, (p.strip() for p in spec.split(","))):
        kid, _, secret = part.partition(":")
        if not kid or len(secret.encode()) < _MIN_SECRET_BYTES:
            raise RuntimeError(f"{env} entries must be 'kid:secret' with >= 32-byte secrets")
        keys[kid] = secret.encode()
    if not keys:
        raise RuntimeError(f"{env} is empty")
    return keys


class Keyring:
    def __init__(self, keys: dict[str, bytes], active_kid: str):
        if active_kid not in keys:
            raise RuntimeError("active key id not present in keyring")
        self._keys = dict(keys)
        self.active_kid = active_kid

    @classmethod
    def load(cls, *, env: str, active_env: str, dev_file: str, dev_prefix: str) -> Keyring:
        spec = os.environ.get(env)
        if spec:
            keys = _parse(spec, env)
        else:
            from src.db.database import DB_PATH  # local: keep this module import-light

            path = Path(DB_PATH).parent / dev_file
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as fh:
                    fh.write(f"{dev_prefix}-{secrets.token_hex(4)}:{secrets.token_urlsafe(48)}")
            except FileExistsError:
                pass
            keys = _parse(path.read_text().strip(), str(path))
        active = os.environ.get(active_env) or next(iter(keys))
        return cls(keys, active)

    def has(self, kid: str) -> bool:
        return kid in self._keys

    def mac(self, kid: str, data: bytes) -> str:
        return hmac.new(self._keys[kid], data, hashlib.sha256).hexdigest()

    def verify(self, kid: str, data: bytes, digest: object) -> bool:
        """Constant-time; unknown key ids fail closed."""
        if not self.has(kid) or not isinstance(digest, str):
            return False
        return hmac.compare_digest(self.mac(kid, data), digest)
