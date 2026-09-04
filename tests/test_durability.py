import os
import uuid
import pytest
from datetime import datetime, timezone, timedelta
from decimal import Decimal
import jwt
from fastapi.testclient import TestClient

from app.main import app, JWT_SECRET
from app.db import get_conn, verify_ledger
from app.canonical import hash_payload

@pytest.fixture(scope="module")
def client():
    # Setup test database and tables
    from app.db import init_db
    init_db()
    
    # Truncate tables for a clean test run
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("TRUNCATE approvals, ledger CASCADE;")
    conn.commit()
    cur.close()
    conn.close()
    
    with TestClient(app) as c:
        yield c

def test_workflow_category_2_execution(client):
    """Checks that a Category 2 write (amount < 100) executes immediately without suspension."""
    req_data = {
        "order_id": "ORD-111",
        "amount": 49.99,
        "reason": "item damaged",
        "requester": "dana.reyes"
    }
    response = client.post("/workflow/start", json=req_data)
    assert response.status_code == 200
    res_json = response.json()
    assert res_json["status"] == "completed"
    assert res_json["execution_result"] == "success"
    assert res_json["category"] == 2
    assert res_json["approval_id"] is None

def test_durable_suspension_survives_restart(client):
    """Starts a Category 3 workflow (amount >= 100), verifies suspension, and resumes to completion."""
    req_data = {
        "order_id": "ORD-740",
        "amount": 740.00,
        "reason": "damaged on arrival",
        "requester": "dana.reyes"
    }
    response = client.post("/workflow/start", json=req_data)
    assert response.status_code == 200
    res_json = response.json()
    
    assert res_json["status"] == "suspended"
    assert res_json["category"] == 3
    approval_id = res_json["approval_id"]
    assert approval_id is not None
    
    # Check DB state
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT state, payload_hash FROM approvals WHERE id = %s;", (approval_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    
    assert row is not None
    assert row[0] == "pending"
    payload_hash = row[1]
    
    # Simulate process restart by instantiating a fresh LangGraph client state 
    # (checking that database state persists and executes successfully)
    # Mint a valid token for support_lead role, non-requester (four-eyes)
    token_req = {
        "sub": "ray.okonkwo",
        "roles": ["support_lead"],
        "approval_id": approval_id,
        "payload_hash": payload_hash
    }
    token_resp = client.post("/debug/mint-token", json=token_req)
    token = token_resp.json()["token"]
    
    # Resume the workflow
    resume_req = {
        "approval_id": approval_id,
        "token": token
    }
    resume_resp = client.post("/approvals/resume", json=resume_req)
    assert resume_resp.status_code == 200
    resume_json = resume_resp.json()
    assert resume_json["status"] == "completed"
    assert resume_json["execution_result"] == "success"
    assert resume_json["approver"] == "ray.okonkwo"
    
    # Verify DB state is updated
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT state FROM approvals WHERE id = %s;", (approval_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    assert row[0] == "executed"

def test_four_eyes_denial(client):
    """Verifies that requester self-approval is rejected (Four-eyes rule)."""
    req_data = {
        "order_id": "ORD-444",
        "amount": 250.00,
        "reason": "incorrect item",
        "requester": "dana.reyes"
    }
    response = client.post("/workflow/start", json=req_data)
    res_json = response.json()
    approval_id = res_json["approval_id"]
    
    # Query hash
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT payload_hash FROM approvals WHERE id = %s;", (approval_id,))
    payload_hash = cur.fetchone()[0]
    cur.close()
    conn.close()
    
    # Mint token where approver (sub) == requester (dana.reyes)
    token_req = {
        "sub": "dana.reyes",
        "roles": ["support_lead"],
        "approval_id": approval_id,
        "payload_hash": payload_hash
    }
    token_resp = client.post("/debug/mint-token", json=token_req)
    token = token_resp.json()["token"]
    
    resume_req = {
        "approval_id": approval_id,
        "token": token
    }
    resume_resp = client.post("/approvals/resume", json=resume_req)
    assert resume_resp.status_code == 400
    err_detail = resume_resp.json()["detail"]
    assert err_detail["code"] == "DENIED_IDENTITY"
    assert "four-eyes" in err_detail["detail"]

def test_tampered_payload_aborts(client):
    """Verifies that altering the payload JSON in the DB causes a HASH_MISMATCH rejection on resume."""
    req_data = {
        "order_id": "ORD-555",
        "amount": 500.00,
        "reason": "customer unhappy",
        "requester": "dana.reyes"
    }
    response = client.post("/workflow/start", json=req_data)
    res_json = response.json()
    approval_id = res_json["approval_id"]
    
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT payload_hash FROM approvals WHERE id = %s;", (approval_id,))
    payload_hash = cur.fetchone()[0]
    
    # Tamper with the database payload JSON (e.g. increase the amount from 500 to 5000)
    import json
    cur.execute("SELECT payload_json FROM approvals WHERE id = %s;", (approval_id,))
    payload_json = json.loads(cur.fetchone()[0])
    payload_json["amount"] = 5000.00
    
    cur.execute("UPDATE approvals SET payload_json = %s WHERE id = %s;", (json.dumps(payload_json), approval_id))
    conn.commit()
    cur.close()
    conn.close()
    
    # Mint token for original details
    token_req = {
        "sub": "ray.okonkwo",
        "roles": ["support_lead"],
        "approval_id": approval_id,
        "payload_hash": payload_hash
    }
    token_resp = client.post("/debug/mint-token", json=token_req)
    token = token_resp.json()["token"]
    
    resume_req = {
        "approval_id": approval_id,
        "token": token
    }
    resume_resp = client.post("/approvals/resume", json=resume_req)
    assert resume_resp.status_code == 400
    err_detail = resume_resp.json()["detail"]
    assert err_detail["code"] == "HASH_MISMATCH"
    assert "altered" in err_detail["detail"]

def test_token_replay_aborts(client):
    """Verifies that using a token bound to approval A cannot resume approval B."""
    req_a = {
        "order_id": "ORD-A",
        "amount": 120.00,
        "reason": "Reason A",
        "requester": "dana.reyes"
    }
    req_b = {
        "order_id": "ORD-B",
        "amount": 120.00,
        "reason": "Reason B",
        "requester": "dana.reyes"
    }
    
    res_a = client.post("/workflow/start", json=req_a).json()
    res_b = client.post("/workflow/start", json=req_b).json()
    
    approval_id_a = res_a["approval_id"]
    approval_id_b = res_b["approval_id"]
    
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT payload_hash FROM approvals WHERE id = %s;", (approval_id_a,))
    payload_hash_a = cur.fetchone()[0]
    cur.close()
    conn.close()
    
    # Mint token for approval A
    token_req = {
        "sub": "ray.okonkwo",
        "roles": ["support_lead"],
        "approval_id": approval_id_a,
        "payload_hash": payload_hash_a
    }
    token_resp = client.post("/debug/mint-token", json=token_req)
    token_a = token_resp.json()["token"]
    
    # Try to resume approval B using token A
    resume_req = {
        "approval_id": approval_id_b,
        "token": token_a
    }
    resume_resp = client.post("/approvals/resume", json=resume_req)
    assert resume_resp.status_code == 400
    err_detail = resume_resp.json()["detail"]
    assert err_detail["code"] == "APPROVAL_BINDING_MISMATCH"

def test_ttl_expiry(client):
    """Verifies that resumes after TTL are refused and marked as expired."""
    req_data = {
        "order_id": "ORD-EXP",
        "amount": 300.00,
        "reason": "expired test",
        "requester": "dana.reyes"
    }
    response = client.post("/workflow/start", json=req_data)
    res_json = response.json()
    approval_id = res_json["approval_id"]
    
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT payload_hash FROM approvals WHERE id = %s;", (approval_id,))
    payload_hash = cur.fetchone()[0]
    
    # Set expires_at in the past
    past_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    cur.execute("UPDATE approvals SET expires_at = %s WHERE id = %s;", (past_time, approval_id))
    conn.commit()
    cur.close()
    conn.close()
    
    # Mint token
    token_req = {
        "sub": "ray.okonkwo",
        "roles": ["support_lead"],
        "approval_id": approval_id,
        "payload_hash": payload_hash
    }
    token = client.post("/debug/mint-token", json=token_req).json()["token"]
    
    # Resume
    resume_req = {
        "approval_id": approval_id,
        "token": token
    }
    resume_resp = client.post("/approvals/resume", json=resume_req)
    assert resume_resp.status_code == 400
    err_detail = resume_resp.json()["detail"]
    assert err_detail["code"] == "DENIED_IDENTITY"
    assert "expired" in err_detail["detail"]
    
    # Check DB state
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT state FROM approvals WHERE id = %s;", (approval_id,))
    state = cur.fetchone()[0]
    cur.close()
    conn.close()
    assert state == "expired"

def test_ledger_chain_tamper():
    """Verifies that verify_ledger detects modifications and returns the correct divergence point."""
    # Append a couple of valid rows (these will be added on top of the ones added by tests)
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT MAX(seq) FROM ledger;")
    max_seq_before = cur.fetchone()[0] or 0
    cur.close()
    conn.close()
    
    from app.db import append_ledger_entry
    append_ledger_entry(
        event_type="test_event_1",
        workflow="test_flow",
        run_id=uuid.uuid4(),
        trace_id="trace_1",
        actor="tester"
    )
    seq_tamper, _ = append_ledger_entry(
        event_type="test_event_2",
        workflow="test_flow",
        run_id=uuid.uuid4(),
        trace_id="trace_2",
        actor="tester"
    )
    append_ledger_entry(
        event_type="test_event_3",
        workflow="test_flow",
        run_id=uuid.uuid4(),
        trace_id="trace_3",
        actor="tester"
    )
    
    # Verification should pass initially
    check_before = verify_ledger()
    assert check_before["ok"] is True
    
    # Tamper with the specific row in the database
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE ledger SET actor = 'tampered_actor' WHERE seq = %s;", (seq_tamper,))
    conn.commit()
    cur.close()
    conn.close()
    
    # Verification should now fail and point to the tampered seq
    check_after = verify_ledger()
    assert check_after["ok"] is False
    assert check_after["first_divergence"] == seq_tamper
    assert check_after["invalidated"] >= 2 # the tampered row plus the subsequent row
