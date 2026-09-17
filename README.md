# Durable Execution & Suspension Service

A high-integrity, crash-resilient workflow engine built for **Governed Enterprise AI Agents** (Autonomy Ladder — Project P27). 

This system enables autonomous AI agents to execute sensitive real-world tasks (such as financial refunds or access grants) with human-in-the-loop oversight. Risky actions automatically suspend, persist safely to PostgreSQL, and can survive complete process crashes and redeployments without losing state or opening fraud loopholes.

---

## Key Features

- **Crash-Proof Suspension (Durable Execution):** Eliminates in-memory waiting. Workflow state is persisted to PostgreSQL using LangGraph's `PostgresSaver`. If the server crashes or restarts while waiting for approval, execution resumes seamlessly without data loss.
- **Dynamic Risk Rubric:** Transactions are automatically classified by risk:
  - **Category 2 (Low Risk, < €100):** Executes immediately without human intervention.
  - **Category 3 (High Risk, ≥ €100):** Pauses execution, generates a unique approval record, and awaits human verification.
- **5-Point Cryptographic & Policy Verification on Resume:**
  1. **Role Verification:** Verifies the approver possesses the required role (e.g., `support_lead`).
  2. **Four-Eyes Principle:** Strictly prevents self-approval (`requester != approver`).
  3. **Approval ID Binding:** Prevents replay attacks by ensuring the token binds to the exact approval record.
  4. **Payload Hash Binding:** Ensures the token binds to the specific payload content.
  5. **Anti-Tamper Re-Hashing:** Re-hashes the stored database payload to guarantee it was not altered via direct SQL modifications while frozen.
- **Strict Canonical Serialization:** Normalizes Datetimes (forced to UTC), Decimals, UUIDs, and sorted dictionary keys. **Strictly rejects floating-point values** (`float`) with a `TypeError` to guarantee cross-platform hash reproducibility.
- **Immutable Hash-Chained Ledger:** Every event (`suspended`, `approved`, `denied`, `executed`) is cryptographically linked to the previous block's SHA-256 hash, using PostgreSQL row locks (`SELECT ... FOR UPDATE`) to prevent concurrency forks.

---

## Workflow Architecture

```mermaid
graph TD
    A[Start Request: POST /workflow/start] --> B{Resolve Risk Rubric}
    B -->|Category 2: < €100| C[Execute Action Immediately]
    B -->|Category 3: ≥ €100| D[suspend]
    D --> E[Save Record in approvals Table]
    E --> F[Checkpoint LangGraph State to Postgres]
    F --> G[Process Halts / Memory Released]
    G -.->|Server Crash / Reboot / Days Pass| H[Pending Approval Survives in DB]
    H --> I[Submit Token: POST /approvals/resume]
    I --> J{Run 5 Security Checks}
    J -->|Pass| K[Reload State & Execute Action]
    J -->|Fail / Expired / Tampered| L[Deny & Log to Immutable Ledger]
    K --> M[Record Completion in Ledger]
```

---

## Tech Stack

- **Language:** Python 3.11+
- **API Framework:** FastAPI & Uvicorn
- **Orchestration & State Machine:** LangGraph (`langgraph`, `langgraph-checkpoint-postgres`)
- **Database:** PostgreSQL (`psycopg-binary`, `psycopg_pool`, `psycopg2-binary`)
- **Security & Tokens:** PyJWT (HMAC-SHA256)
- **Data Validation:** Pydantic v2
- **Testing:** Pytest

---

## Repository Structure

```text
.
├── app/
│   ├── canonical.py       # Canonical JSON serializer and SHA-256 payload hasher
│   ├── db.py              # PostgreSQL pool, schema initialization, ledger hash-chain
│   ├── approvals.py       # Suspend/Resume engine & 5-point verification checks
│   ├── graph.py           # LangGraph StateGraph compiled with PostgresSaver
│   └── main.py            # FastAPI endpoints and custom Swagger UI docs
├── tests/
│   └── test_durability.py # Automated test suite covering all 7 core assertions
├── .env.example           # Configuration template
├── .gitignore             # Excludes .env, .venv, caches, and IDE configs
├── requirements.txt       # Project dependencies
└── README.md              # Project documentation
```

---

## Getting Started

### 1. Prerequisites
- Python 3.11 or higher
- A running PostgreSQL instance (local or containerized)

### 2. Clone the Repository
```bash
git clone https://github.com/Saikeerthana-15/AAI--Assignment.git
cd AAI--Assignment
```

### 3. Set Up Virtual Environment & Dependencies
```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Copy `.env.example` to `.env` and set your PostgreSQL credentials:
```bash
cp .env.example .env
```
Edit `.env`:
```env
DATABASE_URL=postgresql://postgres:yourpassword@localhost:5432/p027
JWT_SECRET=supersecretapprovalkey
```

### 5. Run the Server
```bash
python -m uvicorn app.main:app --reload
```
Once started, open the interactive Swagger UI at:
👉 **[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)**

---

## API Walkthrough

### 1. Initiate a High-Risk Workflow
```http
POST /workflow/start
Content-Type: application/json

{
  "order_id": "ORD-740",
  "amount": 740.00,
  "reason": "damaged on arrival",
  "requester": "dana.reyes"
}
```
**Response:**
```json
{
  "run_id": "9029c667-ef01-4f84-8844-f713f276bec1",
  "thread_id": "thread_9029c667-ef01-4f84-8844-f713f276bec1",
  "category": 3,
  "approval_id": "65482371-83e8-46ef-9fbe-378e5da5ec1a",
  "status": "suspended",
  "execution_result": null
}
```

### 2. View Pending Approvals
```http
GET /approvals/pending
```
Returns all frozen transactions with their `approval_id`, required `approver_role`, expiration timestamp, and `payload_hash`.

### 3. Mint Approval Token
```http
POST /debug/mint-token
Content-Type: application/json

{
  "sub": "ray.okonkwo",
  "roles": ["support_lead"],
  "approval_id": "65482371-83e8-46ef-9fbe-378e5da5ec1a",
  "payload_hash": "3d8666081eb6db2a9bd378ac6c00be121cd100b94f474728d421a242e8cb0557"
}
```

### 4. Resume & Execute
```http
POST /approvals/resume
Content-Type: application/json

{
  "approval_id": "65482371-83e8-46ef-9fbe-378e5da5ec1a",
  "token": "<JWT_TOKEN_FROM_STEP_3>"
}
```
**Response:**
```json
{
  "status": "completed",
  "execution_result": "success",
  "approval_id": "65482371-83e8-46ef-9fbe-378e5da5ec1a",
  "approver": "ray.okonkwo"
}
```

---

## Running Automated Tests

A comprehensive Pytest test suite validates all durability, security, and tamper controls:

```bash
python -m pytest
```

### Test Coverage:
1. `test_workflow_category_2_execution`: Verifies low-value writes execute immediately without pausing.
2. `test_durable_suspension_survives_restart`: Verifies high-risk workflows suspend to PostgreSQL and complete upon valid token submission.
3. `test_four_eyes_denial`: Enforces separation of duties (rejects requester self-approval).
4. `test_tampered_payload_aborts`: Rejects execution if payload values are altered directly in the database while frozen.
5. `test_token_replay_aborts`: Ensures an approval token for Transaction A cannot authorize Transaction B.
6. `test_ttl_expiry`: Ensures late approvals after TTL expiration are refused and marked `expired`.
7. `test_ledger_chain_tamper`: Proves the cryptographic ledger hash-chain detects modified or injected rows.

---

## License

Distributed under the Apache 2.0 License.
