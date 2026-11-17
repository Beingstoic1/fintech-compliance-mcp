---
trigger: always_on
---

1. Reference Architecture: Inspect _reference_repos/agentguard for deterministic policy evaluation and argument-bound single-use approval semantics, and _reference_repos/stripe-ai for clean read/write financial tool separation. Do not copy their files verbatim; synthesize an original fintech domain implementation.
2. Zero-Trust Session Identity: Resolve actor_id, actor_role, and tenant_id strictly from a server-side session token registry. Never trust raw role arguments from the client.
3. Dual-Boundary Guardrails: Validate inputs (RBAC + bounds) BEFORE tool execution and sanitize outputs (PII masking for junior_analyst + prompt-injection stripping) AFTER tool execution.
4. Tamper-Evident Audit Ledger: Solve AgentGuard's non-tamper-proof SQLite limitation by chaining every audit row with SHA-256 (prev_hash + current payload = entry_hash).
5. Four-Eyes Approval Gate: State-mutating tools (request_account_freeze, request_fee_refund) must generate a 15-minute single-use approval_id bound to a SHA-256 digest of the exact tool and arguments. A compliance_officer cannot approve their own request.
