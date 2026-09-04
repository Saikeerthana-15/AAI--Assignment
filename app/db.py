import os
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
from app.canonical import canonical_json, sha256

# Load environment variables
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/p027")

def get_conn(db_name_override=None):
    """Establishes connection to the database. Overrides db name if specified."""
    url = DATABASE_URL
    if db_name_override:
        # Swap database in connection URL
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url)
        # Reconstruct with target db path
        url = urlunparse(parsed._replace(path=f"/{db_name_override}"))
    
    conn = psycopg2.connect(url)
    return conn

def init_db():
    """Checks for database and table existence, creating them if necessary."""
    # 1. Check if database exists, if not, create it
    from urllib.parse import urlparse
    parsed = urlparse(DATABASE_URL)
    db_name = parsed.path.lstrip("/")
    
    try:
        conn = get_conn()
        conn.close()
    except psycopg2.OperationalError as e:
        if "does not exist" in str(e):
            print(f"Database {db_name} does not exist. Creating...")
            # Connect to default postgres DB
            conn_pg = get_conn("postgres")
            conn_pg.autocommit = True
            cur = conn_pg.cursor()
            cur.execute(f"CREATE DATABASE {db_name};")
            cur.close()
            conn_pg.close()
            print(f"Database {db_name} created successfully.")
        else:
            raise e

    # 2. Connect and run schema DDL
    conn = get_conn()
    conn.autocommit = True
    cur = conn.cursor()
    
    # Enable pgcrypto for UUID generation
    cur.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
    
    # Create ledger table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS ledger (
        seq           BIGSERIAL PRIMARY KEY,
        occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
        event_type    TEXT NOT NULL,
        workflow      TEXT NOT NULL,
        run_id        UUID NOT NULL,
        trace_id      TEXT NOT NULL,
        actor         TEXT NOT NULL,
        tool          TEXT,
        category      SMALLINT,
        payload_hash  TEXT,
        approver      TEXT,
        outcome       TEXT NOT NULL,
        detail        JSONB NOT NULL DEFAULT '{}',
        prev_hash     TEXT NOT NULL,
        entry_hash    TEXT NOT NULL
    );
    """)
    
    # Create approvals table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS approvals (
        id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        run_id         UUID NOT NULL,
        thread_id      TEXT NOT NULL,
        node           TEXT NOT NULL,
        workflow       TEXT NOT NULL,
        tool           TEXT NOT NULL,
        payload_json   TEXT NOT NULL,
        payload_hash   TEXT NOT NULL,
        requester      TEXT NOT NULL,
        approver_role  TEXT NOT NULL,
        approver       TEXT,
        approved_at    TIMESTAMPTZ,
        token_hash     TEXT,
        state          TEXT NOT NULL DEFAULT 'pending',
        created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
        expires_at     TIMESTAMPTZ NOT NULL,
        detail         JSONB NOT NULL DEFAULT '{}'
    );
    """)
    
    # Create indexing on pending approvals
    cur.execute("""
    CREATE INDEX IF NOT EXISTS approval_pending_idx 
    ON approvals (approver_role, created_at) 
    WHERE state = 'pending';
    """)
    
    cur.close()
    conn.close()

def make_event_dict(event_type, workflow, run_id, trace_id, actor, tool, category, payload_hash, outcome, detail, prev_hash):
    """Produces a standard dict representing a ledger entry for hashing consistency."""
    return {
        "event_type": event_type,
        "workflow": workflow,
        "run_id": str(run_id),
        "trace_id": trace_id,
        "actor": actor,
        "tool": tool,
        "category": category,
        "payload_hash": payload_hash,
        "outcome": outcome,
        "detail": detail,
        "prev_hash": prev_hash
    }

GENESIS = "0" * 64

def append_ledger_entry(event_type, workflow, run_id, trace_id, actor, tool=None, category=None, payload_hash=None, outcome="success", detail=None, approver=None):
    """Appends an immutable entry to the ledger hash chain. Obtains row lock to prevent forks."""
    if detail is None:
        detail = {}
        
    run_id = str(run_id) if run_id is not None else None
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                # Obtain row lock on the latest ledger entry to serialize appends
                cur.execute("SELECT entry_hash FROM ledger ORDER BY seq DESC LIMIT 1 FOR UPDATE;")
                row = cur.fetchone()
                prev_hash = row[0] if row else GENESIS
                
                # Create standard representation
                event_dict = make_event_dict(
                    event_type=event_type,
                    workflow=workflow,
                    run_id=run_id,
                    trace_id=trace_id,
                    actor=actor,
                    tool=tool,
                    category=category,
                    payload_hash=payload_hash,
                    outcome=outcome,
                    detail=detail,
                    prev_hash=prev_hash
                )
                
                entry_hash = sha256(canonical_json(event_dict).encode("utf-8")).hexdigest()
                
                cur.execute("""
                    INSERT INTO ledger (
                        event_type, workflow, run_id, trace_id, actor, tool, category, 
                        payload_hash, outcome, detail, prev_hash, entry_hash, approver
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING seq;
                """, (
                    event_type, workflow, run_id, trace_id, actor, tool, category,
                    payload_hash, outcome, psycopg2.extras.Json(detail), prev_hash, entry_hash, approver
                ))
                seq = cur.fetchone()[0]
                return seq, entry_hash
    except Exception as e:
        raise e
    finally:
        conn.close()

def verify_ledger(from_seq=1):
    """Verifies ledger chain starting from from_seq. Returns verification summary."""
    conn = get_conn()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        # Fetch rows ordered by seq
        cur.execute("SELECT * FROM ledger WHERE seq >= %s ORDER BY seq ASC;", (from_seq - 1,))
        rows = cur.fetchall()
        
        if not rows:
            return {"ok": True, "first_divergence": None, "invalidated": 0}
            
        # Determine starting prev_hash
        if from_seq == 1:
            prev = GENESIS
            to_verify = rows
        else:
            # First row in list is seq = from_seq - 1 (the anchor predecessor)
            anchor = rows[0]
            prev = anchor["entry_hash"]
            to_verify = rows[1:]
            
        for row in to_verify:
            event_dict = make_event_dict(
                event_type=row["event_type"],
                workflow=row["workflow"],
                run_id=row["run_id"],
                trace_id=row["trace_id"],
                actor=row["actor"],
                tool=row["tool"],
                category=row["category"],
                payload_hash=row["payload_hash"],
                outcome=row["outcome"],
                detail=row["detail"],
                prev_hash=prev
            )
            expected = sha256(canonical_json(event_dict).encode("utf-8")).hexdigest()
            
            if expected != row["entry_hash"]:
                # Count how many subsequent rows are invalidated
                cur.execute("SELECT COUNT(*) FROM ledger WHERE seq >= %s;", (row["seq"],))
                invalidated = cur.fetchone()["count"]
                return {
                    "ok": False, 
                    "first_divergence": row["seq"], 
                    "stored": row["entry_hash"], 
                    "recomputed": expected, 
                    "invalidated": invalidated
                }
            prev = row["entry_hash"]
            
        cur.execute("SELECT MAX(seq) FROM ledger;")
        max_seq = cur.fetchone()["max"] or 0
        return {"ok": True, "checked": (from_seq, max_seq)}
    finally:
        cur.close()
        conn.close()
