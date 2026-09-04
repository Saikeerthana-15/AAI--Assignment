import os
from enum import IntEnum
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from uuid import UUID
import jwt
import psycopg2
from psycopg2.extras import RealDictCursor

from app.canonical import canonical_json, hash_payload, sha256
from app.db import get_conn, append_ledger_entry

JWT_SECRET = os.getenv("JWT_SECRET", "supersecretapprovalkey")
APPROVAL_TTL = timedelta(hours=1) # Default 1 hour TTL

class Category(IntEnum):
    READ = 1
    BOUNDED = 2
    SUSPENDED = 3
    PROHIBITED = 4

@dataclass(frozen=True)
class Rubric:
    scope: int
    reversibility: int
    persistence: int
    approver_role: str | None = None
    require_fields: frozenset[str] = frozenset()
    source: str | None = None

    def __post_init__(self):
        for f in ("scope", "reversibility", "persistence"):
            if getattr(self, f) not in (1, 2, 3):
                raise ValueError(f"{f} must be 1, 2 or 3")
        if self.score >= 8 and self.approver_role is None:
            raise ValueError("a suspending rubric must name an approver_role")

    @property
    def score(self) -> int:
        return self.scope * self.reversibility * self.persistence

@dataclass
class Decision:
    allowed: bool
    code: str | None = None
    detail: str | None = None
    payload: Any = None
    category: Category | None = None
    rubric: Rubric | None = None
    tool: str | None = None
    rule: str | None = None
    approval: Any = None

    @classmethod
    def allow(cls, payload, category, approval=None):
        return cls(allowed=True, code="ALLOW", payload=payload, category=category, approval=approval)

    @classmethod
    def deny(cls, code, detail):
        return cls(allowed=False, code=code, detail=detail)

    @classmethod
    def suspend_decision(cls, tool, payload, rubric, rule):
        return cls(allowed=False, code="SUSPEND", tool=tool, payload=payload, rubric=rubric, rule=rule)

@dataclass
class Claims:
    subject: str
    roles: list[str]

@dataclass
class RequestContext:
    run_id: str
    thread_id: str
    node: str
    workflow: str
    claims: Claims

def suspend(decision: Decision, ctx: RequestContext) -> dict:
    """Freezes the workflow, saves the pending approval to the database, and ledger-logs it."""
    payload_json = canonical_json(decision.payload)
    payload_hash = hash_payload(decision.payload)
    expires_at = datetime.now(timezone.utc) + APPROVAL_TTL
    
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            INSERT INTO approvals (
                run_id, thread_id, node, workflow, tool, payload_json, payload_hash, 
                requester, approver_role, expires_at, state
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending')
            RETURNING *;
        """, (
            ctx.run_id, ctx.thread_id, ctx.node, ctx.workflow, decision.tool,
            payload_json, payload_hash, ctx.claims.subject, 
            decision.rubric.approver_role, expires_at
        ))
        approval_row = cur.fetchone()
        conn.commit()
        
        # Log to ledger
        append_ledger_entry(
            event_type="suspended",
            workflow=ctx.workflow,
            run_id=ctx.run_id,
            trace_id=ctx.thread_id,
            actor=ctx.claims.subject,
            tool=decision.tool,
            category=int(Category.SUSPENDED),
            payload_hash=payload_hash,
            outcome="pending",
            detail={"approval_id": str(approval_row["id"]), "rule": decision.rule}
        )
        return dict(approval_row)
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def resume(approval_id: UUID, token: str) -> Decision:
    """Verifies approval credentials, enforces boundaries, and resumes or denies execution."""
    conn = get_conn()
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Obtain row lock to prevent double resume / race conditions
                cur.execute("SELECT * FROM approvals WHERE id = %s FOR UPDATE;", (str(approval_id),))
                a = cur.fetchone()
                
                if not a:
                    return Decision.deny("DENIED_IDENTITY", "approval not found")
                    
                if a["state"] != "pending":
                    return Decision.deny("DENIED_IDENTITY", f"approval is {a['state']}")
                    
                now_utc = datetime.now(timezone.utc)
                if now_utc > a["expires_at"]:
                    cur.execute("UPDATE approvals SET state = 'expired' WHERE id = %s;", (str(approval_id),))
                    append_ledger_entry(
                        event_type="denied",
                        workflow=a["workflow"],
                        run_id=a["run_id"],
                        trace_id=a["thread_id"],
                        actor="system",
                        tool=a["tool"],
                        category=int(Category.SUSPENDED),
                        payload_hash=a["payload_hash"],
                        outcome="DENIED_IDENTITY",
                        detail={"approval_id": str(approval_id), "detail": "approval expired"}
                    )
                    return Decision.deny("DENIED_IDENTITY", "approval expired")

                # Verify and decode JWT token
                try:
                    claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
                except Exception as jwt_err:
                    return Decision.deny("DENIED_IDENTITY", f"token verification failed: {str(jwt_err)}")

                # Extract fields for convenience
                approver = claims.get("sub")
                roles = claims.get("roles", [])
                token_approval_id = claims.get("approval_id")
                token_payload_hash = claims.get("payload_hash")

                # 5 Security Checks
                checks = [
                    (a["approver_role"] in roles, "DENIED_IDENTITY", 
                     f"approval requires role {a['approver_role']}"),
                    (approver != a["requester"], "DENIED_IDENTITY", 
                     "four-eyes: approver == requester"),
                    (str(token_approval_id) == str(a["id"]), "APPROVAL_BINDING_MISMATCH", 
                     "token binds a different approval"),
                    (token_payload_hash == a["payload_hash"], "HASH_MISMATCH", 
                     "token binds a different payload"),
                    (sha256(a["payload_json"].encode("utf-8")).hexdigest() == a["payload_hash"], "HASH_MISMATCH", 
                     "stored payload has been altered"),
                ]

                for ok, code, detail in checks:
                    if not ok:
                        # Update approval state to denied
                        cur.execute("UPDATE approvals SET state = 'denied', approver = %s WHERE id = %s;", (approver, str(approval_id)))
                        append_ledger_entry(
                            event_type="denied",
                            workflow=a["workflow"],
                            run_id=a["run_id"],
                            trace_id=a["thread_id"],
                            actor=approver or "unknown",
                            tool=a["tool"],
                            category=int(Category.SUSPENDED),
                            payload_hash=a["payload_hash"],
                            outcome=code,
                            detail={"approval_id": str(approval_id), "detail": detail}
                        )
                        return Decision.deny(code, detail)

                # Record successful approval
                token_hash = sha256(token.encode("utf-8")).hexdigest()
                cur.execute("""
                    UPDATE approvals 
                    SET state = 'approved', approver = %s, approved_at = %s, token_hash = %s 
                    WHERE id = %s;
                """, (approver, now_utc, token_hash, str(approval_id)))

            append_ledger_entry(
                event_type="approved",
                workflow=a["workflow"],
                run_id=a["run_id"],
                trace_id=a["thread_id"],
                actor=approver,
                tool=a["tool"],
                category=int(Category.SUSPENDED),
                payload_hash=a["payload_hash"],
                outcome="approved",
                detail={"approval_id": str(approval_id)},
                approver=approver
            )
            
            # Reconstruct payload (e.g. standard dict representing input)
            import json
            payload = json.loads(a["payload_json"])
            
            a_updated = dict(a)
            a_updated["state"] = "approved"
            a_updated["approver"] = approver
            a_updated["approved_at"] = now_utc
            a_updated["token_hash"] = token_hash
            
            return Decision.allow(payload, category=Category.SUSPENDED, approval=a_updated)
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()
