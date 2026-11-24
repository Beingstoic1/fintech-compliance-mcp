"""
Fintech Compliance Officer Workbench — Streamlit App
Institutional Zero-Trust AI Guardrails Console
3-Tab Interactive Enterprise UI: Guardrail Simulator | Four-Eyes Approval Queue | Cryptographic Audit Ledger & Tamper Lab
"""
import json
import sys
from pathlib import Path
from typing import Any

# Ensure repository root is on sys.path so `src...` imports work regardless of launch command
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="Fintech Compliance Workbench · Risk & AI Guardrails",
    page_icon="🏦",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Institutional slate theme. Palette/fonts live in .streamlit/config.toml; tokens below mirror
# docs/assets/site.css so the Workbench and the docs site read as one system.
st.markdown("""
<style>
  :root {
    --bg: #f8fafc;
    --surface: #ffffff;
    --surface-2: #f1f5f9;
    --border: #e2e8f0;
    --border-strong: #cbd5e1;
    --text: #0f172a;
    --text-2: #334155;
    --text-3: #475569;
    --accent: #1e40af;
    --accent-soft: #eff6ff;
    --accent-border: #bfdbfe;
    --pass-fg: #14532d;  --pass-bg: #f0fdf4;  --pass-bd: #bbf7d0;
    --warn-fg: #713f12;  --warn-bg: #fefce8;  --warn-bd: #fde68a;
    --block-fg: #7f1d1d; --block-bg: #fef2f2; --block-bd: #fecaca;
    --info-fg: #1e3a8a;  --info-bg: #eff6ff;  --info-bd: #bfdbfe;
    --font-mono: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    --radius-sm: 4px;
    --radius: 8px;
  }

  h1, h2, h3, h4 { letter-spacing: -0.015em; color: var(--text); }

  /* Monospace for IDs, HMAC digests, policy/reason codes */
  code, pre, .stCode, .mono,
  [data-testid="stMetricValue"] {
    font-family: var(--font-mono) !important;
    font-feature-settings: "tnum" 1, "zero" 1;
  }
  .stMarkdown code, [data-testid="stExpander"] summary code {
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--text);
    padding: 1px 5px;
    font-size: 0.85em;
  }

  /* KPI metric cards: 1px hairline, no heavy shadow */
  [data-testid="stMetric"], [data-testid="metric-container"] {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 14px 16px;
    box-shadow: none;
  }
  [data-testid="stMetricLabel"], [data-testid="stMetricLabel"] p {
    font-size: 11px !important;
    font-weight: 600 !important;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-3) !important;
  }
  [data-testid="stMetricValue"] {
    font-size: 1.6rem !important;
    font-weight: 600 !important;
    color: var(--text);
  }

  /* Surfaces: borders, not shadows */
  [data-testid="stExpander"] details,
  [data-testid="stDataFrame"], [data-testid="stTable"],
  [data-testid="stJson"], .stCode {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: none;
  }
  [data-testid="stDataFrame"], [data-testid="stTable"] { overflow: hidden; }
  [data-testid="stTable"] td, [data-testid="stTable"] th { font-variant-numeric: tabular-nums; }

  .header-tag {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: var(--accent-soft);
    border: 1px solid var(--accent-border);
    color: var(--accent);
    font-family: var(--font-mono);
    font-size: 11px;
    font-weight: 600;
    padding: 3px 10px;
    border-radius: var(--radius-sm);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  /* Semantic decision badges (fg on bg >= 7:1, matching the docs site) */
  .badge-allow, .badge-redact, .badge-escalate, .badge-block {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 3px 10px;
    border: 1px solid;
    border-radius: var(--radius-sm);
    font-family: var(--font-mono);
    font-size: 11px;
    font-weight: 600;
  }
  .badge-allow    { color: var(--pass-fg);  background: var(--pass-bg);  border-color: var(--pass-bd); }
  .badge-redact   { color: var(--warn-fg);  background: var(--warn-bg);  border-color: var(--warn-bd); }
  .badge-escalate { color: var(--info-fg);  background: var(--info-bg);  border-color: var(--info-bd); }
  .badge-block    { color: var(--block-fg); background: var(--block-bg); border-color: var(--block-bd); }

  /* Job-to-be-done callout */
  .jtbd-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent);
    border-radius: var(--radius);
    padding: 16px 20px;
    margin-bottom: 24px;
    font-size: 13px;
    line-height: 1.6;
    color: var(--text-2);
  }
  .jtbd-card .jtbd-title {
    color: var(--text);
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .jtbd-card p { margin: 0; color: var(--text-3); font-size: 13px; }
  .jtbd-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 16px;
    margin-top: 12px;
  }
  .jtbd-item {
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px 14px;
  }
  .jtbd-item strong {
    color: var(--text);
    display: block;
    font-size: 12px;
    margin-bottom: 4px;
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }
  .jtbd-item span { font-size: 12px; color: var(--text-3); }

  .runbook {
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 14px 18px;
    font-size: 13px;
    color: var(--text-2);
    line-height: 1.6;
  }

  .stButton > button {
    font-weight: 600;
    border-radius: 6px;
    box-shadow: none;
    transition: background-color 150ms ease-out, border-color 150ms ease-out;
  }
</style>
""", unsafe_allow_html=True)


def _num(label: str) -> Any:
    """Column config for numeric / monetary values: right-aligned so digits line up."""
    return st.column_config.Column(label, alignment="right")


# Dataframe cells render on canvas (CSS can't reach them): align numerics via column_config.
_AUDIT_COLS: dict[str, Any] = {"event_id": _num("event_id")}

# Auto-initialize and seed DB on startup
try:
    from src.db.audit import get_audit_log, init_audit_table, verify_audit_chain
    from src.db.database import (
        DB_PATH,
        detect_structuring,
        get_account,
        get_transactions,
        init_db,
    )
    from src.demo import tamper_lab
    from src.domain import approvals as fsm
    from src.security.identity import authenticated, call_as, issue_demo_token, verify_jwt
    from src.security.session import DEMO_DIRECTORY
    from src.services import approvals as four_eyes
    from src.services import telemetry as ops
    # Ensure directory and database are initialized
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    init_db()
    init_audit_table()
except Exception as e:
    st.error(f"Startup initialization error: {e}")
    st.stop()

# Header Area with Editorial Fintech Risk Console Identity
col_h1, col_h2 = st.columns([3, 1])
with col_h1:
    st.title("🏦 Fintech Compliance Officer Workbench")
    st.caption("Zero-trust guardrails for AI agents · Model Context Protocol server · HMAC-keyed, checkpointed audit ledger")
with col_h2:
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
    <div style="text-align: right;">
      <span class="badge-escalate">● REFERENCE IMPLEMENTATION · NOT CERTIFIED</span>
    </div>
    """, unsafe_allow_html=True)

# Dedicated Fintech Job-To-Be-Done & Real-World Utility Callout
st.markdown("""
<div class="jtbd-card">
  <div style="display: flex; flex-wrap: wrap; gap: 8px; justify-content: space-between; align-items: center; margin-bottom: 8px;">
    <strong class="jtbd-title">
      Job to be done: guardrails between AI agents and fintech operations
    </strong>
    <span class="header-tag">Reference implementation</span>
  </div>
  <p>
    An AI agent with direct access to a core-banking ledger can issue an unwarranted refund, freeze the wrong account,
    or follow instructions planted in a transaction memo. This server places three controls between the LLM and the ledger:
  </p>
  <div class="jtbd-grid">
    <div class="jtbd-item">
      <strong>1. Identity &amp; least-privilege disclosure</strong>
      <span>Role and tenant come from a verified, transport-bound JWT, never from tool arguments. Junior analysts get masked names, account numbers and tax IDs; counterparty memos arrive unmodified inside an <code>untrusted_text</code> envelope.</span>
    </div>
    <div class="jtbd-item">
      <strong>2. Four-Eyes approval</strong>
      <span>Freezes and refunds are staged as approvals that expire after 15 minutes, bound to their exact arguments with HMAC-SHA256. A different, step-up-authenticated compliance officer must approve; self-approval is rejected.</span>
    </div>
    <div class="jtbd-item">
      <strong>3. Tamper-evident audit</strong>
      <span>Every decision is written to an HMAC-SHA256 chain with append-only triggers and signed checkpoints. The verifier detects edited rows and tail truncation; it cannot prevent them.</span>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# Collapsible 60-Second Guided Demo Banner
with st.expander("⏱️ **Guided walkthrough: three checks across the tabs**", expanded=False):
    st.markdown("""
    <div class="runbook">
      <strong>Operator walkthrough:</strong>
      <ol style="margin-top: 8px; padding-left: 20px;">
        <li><strong>Verify PII Masking:</strong> In <strong>Tab 1</strong>, keep role as <code>junior_alice</code>, select <code>get_account_profile</code> for <code>ACC-001</code>, and click <strong>Run Tool</strong>. Account number masks to <code>****4821</code> and PAN to <code>XXXXX234F</code> (<code>REDACT</code>). Switch role to <code>senior_carol</code> to see the same fields unmasked (<code>ALLOW</code>).</li>
        <li><strong>Four-Eyes Dual-Control:</strong> In <strong>Tab 1</strong>, select <code>senior_carol</code> and run <code>request_account_freeze</code> for <code>ACC-010</code> to generate a 15-minute approval gate. Then switch to <strong>Tab 2</strong> as <code>officer_eve</code> to inspect evidence and click <strong>Approve Only</strong> or <strong>Approve & Execute</strong>. An officer cannot approve their own request (<code>DUAL_CONTROL_VIOLATION</code>).</li>
        <li><strong>Cryptographic Tamper Lab:</strong> Go to <strong>Tab 3</strong> to view the HMAC-keyed audit chain. Click <strong>Simulate Database Tampering</strong> to edit a historical row in SQLite, then see the verifier report the first broken link.</li>
      </ol>
    </div>
    """, unsafe_allow_html=True)

tab1, tab2, tab3, tab4 = st.tabs([
    "🛡️ Agent & Guardrail Simulator",
    "👁️ Four-Eyes Approval Queue",
    "🔐 Cryptographic Audit Ledger & Tamper Lab",
    "📈 Operational Telemetry",
])

# ─── TAB 1: GUARDRAIL SIMULATOR ───────────────────────────────────────────────
with tab1:
    st.header("Live Agent & Guardrail Simulator")

    with st.sidebar:
        st.subheader("Zero-Trust Session")
        role_label = st.selectbox(
            "Active User / Identity",
            list(DEMO_DIRECTORY.keys()),
            index=0,
            help="Dev issuer mints a signed, 15-minute JWT; role and tenant come only from its verified claims"
        )
        session_token = issue_demo_token(role_label)
        try:
            current_session = verify_jwt(session_token)
            st.markdown(f"**Role:** `{current_session.role}`")
            st.markdown(f"**Tenant ID:** `{current_session.tenant_id}`")
            st.markdown(f"**Session Sub:** `{current_session.sub}`")
            st.markdown("**Credential:** signed JWT (exp 15 min), bound out of band — never a tool argument")
        except Exception:
            st.error("UNAUTHENTICATED")

    tool_choice = st.selectbox("Select MCP Tool", [
        "get_account_profile",
        "query_transactions",
        "detect_structuring_anomalies",
        "request_account_freeze",
        "request_fee_refund",
        "execute_approved_action"
    ])

    # Dynamic argument inputs
    args_dict: dict[str, Any] = {}
    if tool_choice == "get_account_profile":
        account_id = st.text_input("account_id", value="ACC-001", help="Try ACC-001 or ACC-005")
        args_dict = {"account_id": account_id}
    elif tool_choice == "query_transactions":
        c1, c2, c3, c4 = st.columns(4)
        account_id = c1.text_input("account_id", value="ACC-005", help="ACC-005 contains the injection transaction TXN-INJ-001")
        start_date = c2.text_input("start_date", value="2026-11-01")
        end_date   = c3.text_input("end_date",   value="2026-11-30")
        limit      = c4.number_input("limit", min_value=1, max_value=100, value=20)
        args_dict = {
            "account_id": account_id,
            "start_date": start_date,
            "end_date": end_date,
            "limit": int(limit)
        }
    elif tool_choice == "detect_structuring_anomalies":
        st.caption("Scoped to your authenticated tenant; there is no tenant argument.")
        threshold_cents = st.number_input("threshold_cents", value=999900, step=1000, help="Sub-threshold structuring limit (default ₹9,999 in paise)")
        args_dict = {"threshold_cents": int(threshold_cents)}
    elif tool_choice == "request_account_freeze":
        account_id = st.text_input("account_id", value="ACC-010")
        reason = st.text_area("reason", value="Suspected sub-threshold smurfing ring activity linked to merchant ACC-015")
        args_dict = {"account_id": account_id, "reason": reason}
    elif tool_choice == "request_fee_refund":
        c1, c2 = st.columns(2)
        txn_id = c1.text_input("transaction_id", value="TXN-N001")
        amount = c2.number_input("amount_cents", min_value=1, value=50000, help="Amount in paise (50000 = ₹500)")
        reason = st.text_area("reason", value="Fee charged erroneously on duplicate debit")
        args_dict = {"transaction_id": txn_id, "amount_cents": int(amount), "reason": reason}
    elif tool_choice == "execute_approved_action":
        approval_id = st.text_input("approval_id", value="", help="Paste an approval_id created by request_account_freeze or request_fee_refund")
        args_dict = {"approval_id": approval_id}

    if st.button("▶️ Run Tool", type="primary"):
        # Every tool runs through the MCP handler under the verified principal: one
        # implementation of RBAC, validation, projection, Four-Eyes, and audit.
        from src.mcp_server import server as mcp_handlers
        res: dict[str, Any] | None = None
        error: str | None = None
        try:
            res = call_as(session_token, getattr(mcp_handlers, tool_choice), **args_dict)
        except Exception:
            # Never surface internal exception text in the UI.
            error = "Request failed: invalid input or internal error"
        if res is not None and res.get("decision") == "BLOCK":
            error = res.get("error", "Blocked")

        if error or res is None:
            st.error(f"🚫 **Action Blocked:** {error or 'no result'}")
        elif tool_choice in ("request_account_freeze", "request_fee_refund"):
            label = ("🔶 **Approval Gate Created!** Requires Compliance Officer Dual-Control"
                     if tool_choice == "request_account_freeze" else "🔶 **Refund Approval Created!**")
            st.success(label)
            st.code(res["approval_id"], language="text")
            st.info("💡 Copy this `approval_id` to approve it in **Tab 2** as `officer_eve`, or execute it with `execute_approved_action`.")
        else:
            # Raw view is fetched for this console only (tenant-scoped); it never reaches the LLM.
            raw_view: Any
            if tool_choice == "get_account_profile":
                raw_view = get_account(args_dict["account_id"], current_session.tenant_id)
            elif tool_choice == "query_transactions":
                raw_view = get_transactions(args_dict["account_id"], args_dict["start_date"] or None,
                                            args_dict["end_date"] or None, args_dict["limit"],
                                            tenant_id=current_session.tenant_id)
            elif tool_choice == "detect_structuring_anomalies":
                raw_view = detect_structuring(current_session.tenant_id, args_dict["threshold_cents"])
            else:
                raw_view = res
            guarded = res.get("data", res)

            decision = res["decision"]
            if decision == "ALLOW":
                st.markdown('<span class="badge-allow">● DECISION: ALLOW (Unmasked Privileged Output)</span>', unsafe_allow_html=True)
            elif decision == "REDACT":
                st.markdown('<span class="badge-redact">● DECISION: REDACT (Fields projected / PII masked)</span>', unsafe_allow_html=True)
            else:
                st.markdown(f'<span class="badge-block">● DECISION: {decision}</span>', unsafe_allow_html=True)

            col_raw, col_guard = st.columns(2)
            with col_raw:
                st.subheader("📋 Raw Database Record")
                st.json(raw_view)
            with col_guard:
                st.subheader("🛡️ Guardrailed Agent Output")
                st.json(guarded)

            rows = guarded if isinstance(guarded, list) else [guarded]
            if any(isinstance(v, dict) and v.get("injection_signals")
                   for r in rows if isinstance(r, dict) for v in r.values()):
                st.warning("⚠️ **Injection signals detected:** the memo is delivered inside an `untrusted_text` envelope. "
                           "It cannot trigger a mutation: those require RBAC plus Four-Eyes sign-off.")

# ─── TAB 2: FOUR-EYES APPROVAL QUEUE ─────────────────────────────────────────
with tab2:
    st.header("👁️ Four-Eyes Approval Queue")
    st.markdown("State-mutating operations require independent approval from an authorized Compliance Officer.")

    co_label = st.selectbox("Acting Compliance Officer",
                            ["officer_eve", "officer_frank"],
                            help="Only compliance_officer roles have approval permissions")
    # Approval console = the out-of-band human channel. Its session carries a step-up
    # `amr` (simulated WebAuthn/MFA in this dev build); MCP agent tokens do not, so an
    # agent can execute only what a human has already signed off here.
    co_token = issue_demo_token(co_label, amr=("pwd", "mfa"))
    try:
        co_session = verify_jwt(co_token)
        st.info(f"**Authenticated Identity:** `{co_session.sub}` | **Role:** `{co_session.role}` | "
                f"**Tenant:** `{co_session.tenant_id}` | **Auth:** `{'+'.join(co_session.amr)}` (step-up)")
    except Exception:
        st.error("UNAUTHENTICATED")
        st.stop()

    if st.button("🔄 Refresh Queue"):
        st.rerun()

    four_eyes.sweep_expired(co_session.tenant_id)
    approvals = four_eyes.list_open(co_session.tenant_id)  # tenant-scoped queue

    if not approvals:
        st.info("📭 No pending approvals. Switch to Tab 1 as `senior_carol` to create an account freeze or refund request.")
    else:
        st.metric("Open Approval Requests", len(approvals))
        for appr in approvals:
            appr_id = appr["approval_id"]
            with st.expander(f"🔶 `{appr['tool_name']}` · ID `{appr_id[:12]}…` · requested by `{appr['requester_sub']}`"):
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown(f"**Tenant ID:** `{appr['tenant_id']}`")
                    st.markdown(f"**Requester Sub:** `{appr['requester_sub']}`")
                    st.markdown(f"**Requester Role:** `{appr['requester_role']}`")
                    st.markdown(f"**Created At (UTC):** {appr['created_at']}")
                    st.markdown(f"**Expires At (UTC):** {appr['expires_at']}")
                    st.markdown(f"**Binding:** HMAC-SHA256 · key `{appr['key_id']}`")
                    if appr["status"] == fsm.APPROVED:
                        st.markdown(f'<span class="badge-allow">● STATUS: APPROVED by {appr["approver_sub"]} (AWAITING EXECUTION)</span>', unsafe_allow_html=True)
                    else:
                        st.markdown('<span class="badge-escalate">● STATUS: AWAITING APPROVAL</span>', unsafe_allow_html=True)

                with c2:
                    st.markdown("**Bound Canonical Arguments:**")
                    try:
                        st.json(json.loads(appr["canonical_args_json"]))
                    except Exception:
                        st.code(appr["canonical_args_json"])

                if appr["requester_sub"] == co_session.sub:
                    st.error("🔒 **DUAL_CONTROL_VIOLATION**: Four-Eyes invariant prohibits self-approval. A different officer must approve.")
                    continue

                # All rules are enforced by the service; the UI only routes clicks.
                from src.mcp_server.server import execute_approved_action, reject_approved_action
                b1, b2, b3 = st.columns(3)
                if appr["status"] == fsm.PENDING:
                    if b1.button("✅ Approve Only", key=f"appr_{appr_id}"):
                        with authenticated(co_token) as officer:
                            res = four_eyes.approve(officer, appr_id)
                        (st.success if res["decision"] == "APPROVED" else st.error)(
                            "✅ Request Approved! Ready for execution." if res["decision"] == "APPROVED"
                            else f"Approval error: {res.get('error')}")
                        st.rerun()
                else:
                    b1.info("Already Approved")

                btn_label = "⚡ Approve & Execute" if appr["status"] == fsm.PENDING else "▶️ Execute Action"
                if b2.button(btn_label, key=f"exec_{appr_id}", type="primary"):
                    res = {"decision": fsm.APPROVED}
                    if appr["status"] == fsm.PENDING:
                        with authenticated(co_token) as officer:
                            res = four_eyes.approve(officer, appr_id)
                    if res["decision"] == fsm.APPROVED:
                        res = call_as(co_token, execute_approved_action, appr_id)
                    if res.get("decision") == "EXECUTED":
                        st.success(f"⚡ Successfully executed: {res.get('action')}")
                    else:
                        st.error(f"Execution error: {res.get('error')}")
                    st.rerun()

                if b3.button("❌ Reject", key=f"rej_{appr_id}"):
                    res = call_as(co_token, reject_approved_action, appr_id, "Rejected in approval console")
                    st.error("❌ Request Rejected." if res.get("decision") == "REJECTED"
                             else f"Reject error: {res.get('error')}")
                    st.rerun()

# ─── TAB 3: AUDIT LEDGER & TAMPER LAB ────────────────────────────────────────
with tab3:
    st.header("🔐 Cryptographic Audit Ledger & Tamper Lab")
    st.markdown(
        "Every event is chained with a keyed HMAC-SHA256 "
        "(`entry_hash = HMAC(key[key_id], canonical_json(event_id, prev_hash, ts, actor, tenant, tool, args_digest, decision, detail))`). "
        "In-app UPDATE/DELETE is aborted by triggers, and signed checkpoints in an external store detect "
        "truncation of the newest rows. Tamper-evident, not tamper-proof: it detects changes, it cannot prevent them."
    )

    logs = get_audit_log(limit=200)
    if logs:
        df = pd.DataFrame(logs)
        df["prev_hash_short"]  = df["prev_hash"].str[:16] + "..."
        df["entry_hash_short"] = df["entry_hash"].str[:16] + "..."

        display_cols = ["event_id", "timestamp_utc", "session_sub", "actor_role",
                        "tenant_id", "tool_name", "decision",
                        "prev_hash_short", "entry_hash_short"]
        avail = [c for c in display_cols if c in df.columns]
        st.dataframe(df[avail], width="stretch", height=280, column_config=_AUDIT_COLS)
        st.metric("Total Cryptographic Log Rows", len(logs))
    else:
        st.info("No audit logs yet. Run tools in Tab 1 to populate the ledger.")

    st.markdown("---")

    col_v, col_t = st.columns(2)

    with col_v:
        st.subheader("🔍 Cryptographic Chain Verifier")
        st.caption("Streams every row from event 1, then checks the latest signed external checkpoint.")
        if st.button("Verify Full Chain Integrity", type="primary"):
            res = verify_audit_chain()
            if res["ok"]:
                st.success(f"✅ **CHAIN INTACT:** {res['checked']} HMAC links verified; "
                           f"checkpoint at event {res.get('checkpoint_event_id')} matches.")
            else:
                st.error(
                    f"❌ **TAMPER DETECTED:** `{res.get('reason')}` at `event_id = {res.get('corrupted_event_id')}`\n\n"
                    f"{res.get('message')}"
                )

    with col_t:
        st.subheader("🧪 Live Tamper Lab")
        st.caption("Simulates an attacker with raw DB-file access: drops the append-only triggers, edits a row.")
        if not tamper_lab.enabled():
            st.info("Tamper lab is disabled in production (FINTECH_ENV=production).")
        elif st.button("💥 Simulate Database Tampering", type="secondary"):
            if logs:
                target_id = logs[0]["event_id"]
                curr_dec = logs[0]["decision"]
                tampered_dec = "ALLOW" if curr_dec != "ALLOW" else "BLOCK"
                tamper_lab.tamper_row(target_id, tampered_dec)
                st.warning(f"🔧 Raw SQLite update executed: `event_id={target_id}` decision set to `{tampered_dec}` "
                           "without the HMAC key, so its entry_hash cannot be recomputed.")

                check = verify_audit_chain()
                if not check["ok"]:
                    st.error(f"🔒 **VERIFIER CAUGHT TAMPERING!** Broken link detected at `event_id = {check.get('corrupted_event_id')}`.")
                else:
                    st.error("Verifier failed to detect tampering.")
            else:
                st.warning("Generate events in Tab 1 first.")

        if tamper_lab.enabled() and st.button("🔄 Restore Chain to Valid State"):
            if logs:
                target_id = logs[0]["event_id"]
                tamper_lab.restore_row(target_id)
                check = verify_audit_chain()
                if check["ok"]:
                    st.success("✅ Chain restored and verified!")
                else:
                    st.info("Chain reset complete.")
                st.rerun()

    with st.expander("🔎 View Full Cryptographic Payload"):
        if logs:
            st.dataframe(pd.DataFrame(logs), width="stretch", column_config=_AUDIT_COLS)


# ─── TAB 4: OPERATIONAL TELEMETRY (T24) ──────────────────────────────────────
def _ms(v: Any) -> str:
    return f"{v:.3f} ms"


def _secs(v: Any) -> str:
    return f"{v:.1f} s"


with tab4:
    st.header("📈 Operational Telemetry")
    st.caption("Tool latency and block reasons come from `tool_telemetry`: tool name, audited decision, "
               "reason code and latency only (no arguments, identities, PII or tokens), across all tenants. "
               "Four-Eyes figures are scoped to the selected tenant.")

    ops_tenant = st.selectbox("Tenant (Four-Eyes metrics)",
                              sorted({t for _, t in DEMO_DIRECTORY.values()}), key="ops_tenant")
    if st.button("🔄 Refresh Telemetry"):
        st.rerun()
    four_eyes.sweep_expired(ops_tenant)
    dash = ops.dashboard(ops_tenant)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Tool Calls (window)", dash.window)
    m2.metric("Blocked Actions", sum(n for _, n in dash.blocked))
    if dash.turnaround:
        m3.metric("Four-Eyes Turnaround p50", _secs(dash.turnaround.median_s))
        m4.metric("Four-Eyes Turnaround p95", _secs(dash.turnaround.p95_s))
    else:
        m3.metric("Four-Eyes Turnaround p50", "n/a")
        m4.metric("Four-Eyes Turnaround p95", "n/a")

    st.metric("Approval Expiry Rate",
              "n/a" if dash.expiry_rate is None else f"{dash.expiry_rate * 100:.1f} %",
              help=f"EXPIRED / (CONSUMED + REJECTED + EXPIRED) over {dash.terminal_approvals} closed approvals")

    c_lat, c_blk = st.columns(2)
    with c_lat:
        st.subheader("Tool Latency (p50 / p95)")
        if dash.latency:
            st.dataframe(pd.DataFrame([{"tool": s.tool, "calls": s.calls, "p50": _ms(s.p50_ms), "p95": _ms(s.p95_ms)}
                                       for s in dash.latency]), width="stretch", hide_index=True,
                         column_config={"calls": _num("calls"), "p50": _num("p50"), "p95": _num("p95")})
        else:
            st.info("No tool calls recorded yet. Run tools in Tab 1.")
    with c_blk:
        st.subheader("Blocked Actions by Reason Code")
        if dash.blocked:
            st.dataframe(pd.DataFrame(dash.blocked, columns=["reason_code", "count"]),
                         width="stretch", hide_index=True, column_config={"count": _num("count")})
        else:
            st.info("No blocked actions recorded.")
