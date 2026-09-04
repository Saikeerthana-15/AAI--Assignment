import json
from decimal import Decimal
from datetime import datetime, date, timezone
from uuid import UUID
from hashlib import sha256
from typing import Any
from pydantic import BaseModel

def canonical_json(obj: Any) -> str:
    """Produces a canonical, byte-identical JSON string for equivalent payloads."""
    return json.dumps(_norm(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def _norm(o: Any) -> Any:
    if isinstance(o, BaseModel):
        return _norm(o.model_dump(mode="json"))
    if isinstance(o, Decimal):
        # Normalize decimal (e.g. 740.00 -> 740) and output as a float-free string
        return format(o.normalize(), "f")
    if isinstance(o, datetime):
        # Force UTC and output standard ISO format
        utc_dt = o.astimezone(timezone.utc)
        return utc_dt.isoformat()
    if isinstance(o, date):
        return o.isoformat()
    if isinstance(o, UUID):
        return str(o)
    if isinstance(o, (set, frozenset)):
        return sorted(_norm(v) for v in o)
    if isinstance(o, dict):
        return {str(k): _norm(v) for k, v in sorted(o.items())}
    if isinstance(o, (list, tuple)):
        return [_norm(v) for v in o]
    if isinstance(o, float):
        raise TypeError("float in a hashed payload — use Decimal")
    return o

def hash_payload(obj: Any) -> str:
    """Returns the SHA256 hex digest of the canonical JSON representation of the object."""
    return sha256(canonical_json(obj).encode("utf-8")).hexdigest()
