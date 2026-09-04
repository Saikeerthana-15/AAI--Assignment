import os
from typing import TypedDict, Optional
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.postgres import PostgresSaver
from psycopg_pool import ConnectionPool

from app.db import DATABASE_URL, init_db, append_ledger_entry, get_conn
from app.approvals import suspend, Decision, RequestContext, Claims, Category

class WorkflowState(TypedDict):
    payload: dict
    requester: str
    category: int
    approver_role: Optional[str]
    approval_id: Optional[str]
    approval_status: str # 'pending', 'approved', 'denied'
    outcome: Optional[str]
    execution_result: Optional[str]
    run_id: str
    thread_id: str

# Initialize DB first to ensure database and tables exist before connection pool starts
init_db()

# Create connection pool for PostgresSaver with autocommit=True
pool = ConnectionPool(conninfo=DATABASE_URL, max_size=10, kwargs={"autocommit": True})
saver = PostgresSaver(pool)
# Initialize Saver tables
saver.setup()

def check_risk(state: WorkflowState) -> dict:
    """Classifies risk based on transaction amount."""
    payload = state["payload"]
    amount = float(payload.get("amount", 0))
    
    # Amount >= 100 triggers Category 3 (Suspended), requiring role support_lead
    if amount >= 100.0:
        category = 3
        approver_role = "support_lead"
    else:
        category = 2
        approver_role = None
        
    return {
        "category": category,
        "approver_role": approver_role,
        "approval_status": "pending" if category == 3 else "bypass"
    }

def suspend_node(state: WorkflowState) -> dict:
    """Handles the suspension registration if risk is Category 3 and not yet approved."""
    if state["category"] == 3 and not state.get("approval_id"):
        # Build Decision and RequestContext
        from decimal import Decimal
        # Re-parse amount as Decimal for canonical checks
        payload_dec = state["payload"].copy()
        payload_dec["amount"] = Decimal(str(payload_dec["amount"]))
        
        dec = Decision.suspend_decision(
            tool="issue_refund",
            payload=payload_dec,
            rubric=Decision(
                allowed=False,
                rubric=None # we don't need it, we'll build it
            ),
            rule="amount_threshold"
        )
        
        # Build Rubric
        from app.approvals import Rubric
        rubric = Rubric(
            scope=1,
            reversibility=3,
            persistence=3,
            approver_role=state["approver_role"]
        )
        dec.rubric = rubric
        
        # Request context
        ctx = RequestContext(
            run_id=state["run_id"],
            thread_id=state["thread_id"],
            node="suspend_node",
            workflow="refund_workflow",
            claims=Claims(subject=state["requester"], roles=[])
        )
        
        # Save suspended approval
        approval_row = suspend(dec, ctx)
        
        return {
            "approval_id": str(approval_row["id"]),
            "approval_status": "pending"
        }
    return {}

def execute_node(state: WorkflowState) -> dict:
    """Executes the transaction after ensuring approval checks pass."""
    payload = state["payload"]
    run_id = state["run_id"]
    thread_id = state["thread_id"]
    requester = state["requester"]
    
    # Double-check database state for safety (Defense-in-depth)
    if state["category"] == 3:
        approval_id = state.get("approval_id")
        if not approval_id:
            raise SecurityError("Execution attempted on Category 3 workflow without approval reference.")
            
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT state, approver FROM approvals WHERE id = %s;", (approval_id,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        
        if not row or row[0] != "approved":
            # State is not approved, raise exception
            status = row[0] if row else "not_found"
            raise SecurityError(f"Execution blocked: approval state is '{status}', expected 'approved'.")
            
        approver = row[1]
        
        # Mark as executed in the DB
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("UPDATE approvals SET state = 'executed' WHERE id = %s;", (approval_id,))
        conn.commit()
        cur.close()
        conn.close()
        
        # Ledger logging of execution
        append_ledger_entry(
            event_type="executed",
            workflow="refund_workflow",
            run_id=run_id,
            trace_id=thread_id,
            actor=requester,
            tool="issue_refund",
            category=3,
            payload_hash=state.get("approval_id"), # we can use approval_id reference
            outcome="executed",
            detail={"approval_id": approval_id, "approver": approver}
        )
    else:
        # Category 2 write - straight execute and ledger
        append_ledger_entry(
            event_type="executed",
            workflow="refund_workflow",
            run_id=run_id,
            trace_id=thread_id,
            actor=requester,
            tool="issue_refund",
            category=2,
            outcome="executed",
            detail={"message": "executed without suspension"}
        )
        
    return {
        "execution_result": "success",
        "outcome": "completed"
    }

def suspend_wait_node(state: WorkflowState) -> dict:
    """Dummy node that serves as the checkpoint interruption point."""
    return {}

def route_after_suspend(state: WorkflowState) -> str:
    """Routes dynamically based on risk category and approval state."""
    if state["category"] == 3:
        if state.get("approval_status") == "approved":
            return "execute_node"
        else:
            return "suspend_wait_node"
    return "execute_node"

# Define workflow graph
builder = StateGraph(WorkflowState)
builder.add_node("check_risk", check_risk)
builder.add_node("suspend_node", suspend_node)
builder.add_node("suspend_wait_node", suspend_wait_node)
builder.add_node("execute_node", execute_node)

builder.add_edge(START, "check_risk")
builder.add_edge("check_risk", "suspend_node")

# Dynamic routing from suspend_node
builder.add_conditional_edges(
    "suspend_node",
    route_after_suspend,
    {
        "suspend_wait_node": "suspend_wait_node",
        "execute_node": "execute_node"
    }
)

# Connect wait node to execution
builder.add_edge("suspend_wait_node", "execute_node")
builder.add_edge("execute_node", END)

# Compile graph with interruption before the wait node
graph = builder.compile(
    checkpointer=saver,
    interrupt_before=["suspend_wait_node"]
)
