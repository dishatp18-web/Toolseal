# TOOLSEAL — AI Agent Runtime Security & Trust Monitoring Platform

> **Every AI Tool Call Must Earn Your Trust.**

Built for the **Global AI Hackathon** (powered by Geek Room, title partner **Bifrost**), **TOOLSEAL** is an AI Agent Runtime Security and Trust Monitoring gateway that inspects MCP and agent tool calls before execution, verifies tool integrity via SHA-256 schema fingerprinting (**Tool DNA**), enforces deterministic risk policies, routes sensitive operations to human administrators, and integrates with **Maxim AI's Bifrost MCP Gateway**.

---

## 1. Problem Statement

Modern AI agents autonomously invoke external tools—databases, filesystems, CRM APIs, and Model Context Protocol (MCP) servers. This creates critical runtime attack surfaces:

- **Sensitive Data Exposure**: Prompt injections or misconfigured agents reading `/etc/shadow`, `.env`, or SSH keys.
- **Bulk Data Exfiltration**: Agents dumping entire customer tables via unbounded `scope` or `limit` parameters.
- **Destructive Commands**: Irreversible mass deletions (`delete_all_records`, `DROP TABLE`) triggered by autonomous loops.
- **MCP Tool Poisoning / Rug-Pulls**: An external MCP server silently mutating a tool's parameter schema after initial approval to introduce hidden exfiltration webhooks or auth-bypass flags.

## 2. Proposed Solution & Core Innovation

**Core Innovation: Continuous Trust Verification of AI Agent Tools**

Instead of trusting a tool simply because it was registered once or relying on a non-deterministic LLM judge for critical security gates, TOOLSEAL enforces a deterministic runtime control plane:

1. **Intelligent Security Engine**: Evaluates every tool call deterministically (0–100 risk score) across tool identity, argument patterns, path traversal, bulk thresholds, injection signatures, and active policy rules (`0–30 ALLOW`, `31–70 REVIEW`, `71–100 BLOCK`).
2. **Tool DNA (SHA-256 Schema Fingerprinting)**: Canonicalizes every registered MCP tool schema into sorted JSON and generates a cryptographic SHA-256 fingerprint. Any post-approval parameter addition, removal, or mutation immediately flags the tool as `modified`/`untrusted`, generates a parameter-level diff, and raises a critical integrity incident.
3. **Human Approval Center with Mandatory Revalidation**: `REVIEW` calls enter a human-in-the-loop approval queue. When an administrator approves a request, TOOLSEAL **revalidates** the call against current Tool DNA integrity and active policy before allowing sandbox execution.
4. **Bifrost MCP Gateway Adapter**: Designed around Bifrost's `MCPPlugin` lifecycle (`PreMCPHook` and `PostMCPHook`), supporting both standalone **DEMO MODE** and live Bifrost HTTP bridge / native Go `.so` plugin integration.

---

## 3. Architecture

```text
AI Agent / Client
       │
       ▼
Bifrost MCP Gateway (Go Plugin: PreMCPHook / PostMCPHook)
   OR  TOOLSEAL Attack Simulator / Direct API
       │
       ▼
TOOLSEAL Runtime Inspection Gateway (Node.js + Express + WebSockets)
  ├── Tool DNA Verifier (Canonical JSON + SHA-256 + Diff Engine)
  ├── Deterministic Security Engine (0–100 Risk Scoring & Policy Gate)
  ├── Approval Workflow & Revalidation Engine
  └── SQLite Persistence Layer (11 Relational Tables)
       │
       ├── ALLOW  ──▶ Safe Execution / PostMCPHook Telemetry
       ├── REVIEW ──▶ Human Approval Center ──▶ Revalidate ──▶ Execute / Reject
       └── BLOCK  ──▶ Short-Circuit & Security Incident Log + Live WS Broadcast
```

---

## 4. Technology Stack

- **Frontend**: React 19, TypeScript, Tailwind CSS v4, Lucide React, Recharts
- **Backend**: Node.js, Express, REST APIs, `ws` WebSockets, Zod validation
- **Database**: SQLite (`better-sqlite3` with WAL mode and foreign key constraints)
- **Security**: Node `crypto` SHA-256 schema fingerprinting, deterministic rule scoring, role-based approval revalidation, isolated safe mock sandbox
- **Gateway Bridge**: TypeScript Bifrost Adapter + native Go plugin bridge template (`/bifrost-plugin/toolseal_plugin.go`)

---

## 5. Installation & Execution

### Prerequisites
- Node.js 20+
- npm 10+

### Setup
```bash
# 1. Install dependencies
npm install

# 2. Configure environment variables (optional; defaults work out of the box)
cp .env.example .env

# 3. Start development server (Express + WebSockets + Vite on port 3000)
npm run dev
```

Open `http://localhost:3000` in your browser. SQLite automatically initializes `./data/toolseal.db` with baseline Tool DNA fingerprints and sample telemetry.

### Production Build
```bash
npm run build
NODE_ENV=production npm start
```

---

## 6. Bifrost Gateway Integration

TOOLSEAL prepares integration around Maxim AI's Bifrost `MCPPlugin` lifecycle (`PreMCPHook` and `PostMCPHook` in `github.com/maximhq/bifrost`):

- **PreMCPHook Bridge (`POST /api/bifrost/pre-mcp-hook`)**: Inspects tool name, arguments, and optional schema before downstream MCP execution. Returns `{ allow, short_circuit, decision, risk_score, reason }`.
- **PostMCPHook Bridge (`POST /api/bifrost/post-mcp-hook`)**: Records execution duration, success/failure status, and telemetry logs.
- **Native Go Plugin Template (`/bifrost-plugin/toolseal_plugin.go`)**: Demonstrates calling TOOLSEAL's Pre/Post hooks from a Go plugin compiled with `-buildmode=plugin`.
- **Honest Integration Limitations**:
  - Go plugins (`-buildmode=plugin`) require exact Go compiler and `github.com/maximhq/bifrost/core/schemas` module version alignment with the host Bifrost binary.
  - Because an external Bifrost server may not be running in every evaluation environment, TOOLSEAL ships in **DEMO MODE** by default and clearly distinguishes `demo` vs `live` events. The **Test Connection** tool performs a real HTTP check and never fabricates a successful connection.

---

## 7. Demo Instructions (Attack Simulator)

Navigate to **Attack Simulator** in the sidebar to run all five live backend scenarios:

1. **Normal Operation**: `get_weather({"city":"Mumbai"})` -> `ALLOW` (executes in safe mock sandbox).
2. **Sensitive File Access**: `read_file({"path":"/etc/shadow"})` -> `BLOCK` or `REVIEW` (dynamically follows your active Security Policy in **Settings**).
3. **Data Exfiltration**: `export_customer_database({"scope":"all_customers"})` -> `BLOCK` + Critical Incident.
4. **Destructive Operation**: `delete_all_records({"confirmation":true})` -> `BLOCK` + Critical Incident.
5. **Tool Schema Manipulation (Tool DNA)**: Registers `invoice_lookup_mcp`, injects hidden `exfiltrate_webhook` and `bypass_auth` parameters, detects SHA-256 fingerprint mismatch, displays side-by-side schema diff, flags tool as `untrusted`, and blocks execution.

---

## 8. REST API Documentation

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Service health & WebSocket client count |
| `GET` | `/api/dashboard/overview` | Real-time aggregated metrics, charts, incidents, and feed |
| `GET` | `/api/executions` | List tool execution telemetry (`?decision=BLOCK&source=bifrost`) |
| `POST` | `/api/executions/inspect` | Inspect a tool call through the Security Engine |
| `POST` | `/api/simulator/run` | Execute one of the 5 Attack Simulator scenarios |
| `GET` | `/api/tools` | List all registered tools and SHA-256 Tool DNA fingerprints |
| `POST` | `/api/tools` | Register a new tool and generate its baseline SHA-256 DNA |
| `PUT` | `/api/tools/:id/schema` | Submit schema update; detects drift and flags `modified` |
| `POST` | `/api/tools/:id/approve-fingerprint` | Approve latest schema fingerprint as trusted baseline |
| `POST` | `/api/tools/:id/revoke` | Flag a tool as `untrusted` |
| `GET` | `/api/tools/:id/diff` | Compare approved baseline schema vs latest schema |
| `GET` | `/api/approvals` | List approval requests (`?status=pending`) |
| `POST` | `/api/approvals/:id/decide` | Approve (with mandatory revalidation) or reject a pending request |
| `GET` | `/api/incidents` | Filter security incidents by `severity`, `status`, date range, or search |
| `PATCH` | `/api/incidents/:id` | Update incident investigation/resolution status |
| `GET` / `PUT` | `/api/policies` / `/api/policies/:id` | View and update deterministic policy thresholds |
| `GET` / `PUT` | `/api/bifrost/config` | View or update Bifrost integration mode & endpoint |
| `POST` | `/api/bifrost/test` | Perform real HTTP health check against Bifrost endpoint |
| `POST` | `/api/bifrost/pre-mcp-hook` | Bifrost `PreMCPHook` security inspection endpoint |
| `POST` | `/api/bifrost/post-mcp-hook` | Bifrost `PostMCPHook` telemetry endpoint |
| `GET` | `/api/bifrost/logs` | View Bifrost integration event logs |
| `GET` | `/api/bifrost/go-plugin` | Retrieve native Go plugin bridge source code |
| `GET` | `/api/audit-logs` | Retrieve immutable administrative & security audit trail |
