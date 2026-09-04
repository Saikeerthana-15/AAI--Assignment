import os
import uuid
from typing import List, Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
import jwt

from app.db import init_db, get_conn
from app.graph import graph
from app.approvals import resume, JWT_SECRET, Category

# Initialize database tables on server startup
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="Durable Execution & Suspension Service (P27)", lifespan=lifespan)

class WorkflowStartRequest(BaseModel):
    order_id: str
    amount: float
    reason: str
    requester: str

class ResumeRequest(BaseModel):
    approval_id: str
    token: str

class MintTokenRequest(BaseModel):
    sub: str
    roles: List[str]
    approval_id: str
    payload_hash: str

@app.post("/workflow/start")
def start_workflow(req: WorkflowStartRequest):
    run_id = uuid.uuid4()
    thread_id = f"thread_{run_id}"
    
    # Establish initial state
    initial_state = {
        "payload": {
            "order_id": req.order_id,
            "amount": req.amount,
            "reason": req.reason
        },
        "requester": req.requester,
        "category": 1,
        "approver_role": None,
        "approval_id": None,
        "approval_status": "pending",
        "outcome": None,
        "execution_result": None,
        "run_id": str(run_id),
        "thread_id": thread_id
    }
    
    config = {"configurable": {"thread_id": thread_id}}
    
    try:
        # Invoke LangGraph
        state = graph.invoke(initial_state, config)
        
        # Check current state in memory
        status_str = "completed"
        if state.get("category") == 3 and not state.get("execution_result"):
            status_str = "suspended"
            
        return {
            "run_id": str(run_id),
            "thread_id": thread_id,
            "category": state.get("category"),
            "approval_id": state.get("approval_id"),
            "status": status_str,
            "execution_result": state.get("execution_result")
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Workflow failed to start: {str(e)}"
        )

@app.get("/approvals/pending")
def list_pending_approvals(role: Optional[str] = None):
    conn = get_conn()
    cur = conn.cursor()
    try:
        if role:
            cur.execute("""
                SELECT id, run_id, thread_id, node, workflow, tool, payload_json, payload_hash, 
                       requester, approver_role, expires_at, state, created_at 
                FROM approvals 
                WHERE state = 'pending' AND approver_role = %s
                ORDER BY created_at ASC;
            """, (role,))
        else:
            cur.execute("""
                SELECT id, run_id, thread_id, node, workflow, tool, payload_json, payload_hash, 
                       requester, approver_role, expires_at, state, created_at 
                FROM approvals 
                WHERE state = 'pending'
                ORDER BY created_at ASC;
            """)
        rows = cur.fetchall()
        
        results = []
        for r in rows:
            results.append({
                "id": str(r[0]),
                "run_id": str(r[1]),
                "thread_id": r[2],
                "node": r[3],
                "workflow": r[4],
                "tool": r[5],
                "payload_json": r[6],
                "payload_hash": r[7],
                "requester": r[8],
                "approver_role": r[9],
                "expires_at": r[10].isoformat(),
                "state": r[11],
                "created_at": r[12].isoformat()
            })
        return results
    finally:
        cur.close()
        conn.close()

@app.post("/approvals/resume")
def resume_workflow(req: ResumeRequest):
    try:
        approval_uuid = uuid.UUID(req.approval_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid approval_id UUID format."
        )

    # 1. Call core resume logic to perform the checks and update row state in DB
    decision = resume(approval_uuid, req.token)
    
    if not decision.allowed:
        # Return error matching the spec (denial code and details)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": decision.code,
                "detail": decision.detail
            }
        )

    # 2. Extract thread information from DB (or decision) to resume graph
    approval_data = decision.approval
    thread_id = approval_data["thread_id"]
    
    config = {"configurable": {"thread_id": thread_id}}
    
    # Update LangGraph state for this thread to mark it as approved
    graph.update_state(config, {"approval_status": "approved"}, as_node="suspend_node")
    
    # Resume invoking the graph
    res_state = graph.invoke(None, config)
    
    return {
        "status": "completed",
        "execution_result": res_state.get("execution_result"),
        "approval_id": req.approval_id,
        "approver": approval_data.get("approver")
    }

@app.post("/debug/mint-token")
def mint_token(req: MintTokenRequest):
    """Debug endpoint to easily sign JWT approval tokens."""
    payload = {
        "sub": req.sub,
        "roles": req.roles,
        "approval_id": req.approval_id,
        "payload_hash": req.payload_hash
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return {"token": token}
