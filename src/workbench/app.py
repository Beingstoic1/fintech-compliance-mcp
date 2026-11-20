"""
Fintech Compliance Officer Workbench — Streamlit App
3-tab interactive enterprise UI: Guardrail Simulator | Approval Queue | Audit Ledger & Tamper Lab
"""
import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

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

# Custom Enterprise Risk Console CSS
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

  html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }
  code, pre, .stCode, [data-testid="stMetricValue"] {
    font-family: 'JetBrains Mono', monospace !important;
  }

  /* Metric cards hairline styling */
  [data-testid="metric-container"] {
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 8px;
    padding: 12px 16px;
    background-color: rgba(255, 255, 255, 0.02);
  }

  /* Semantic badges */
  .badge-allow {
    background-color: rgba(16, 185, 129, 0.15);
    color: #34d399;
    border: 1px solid rgba(16, 185, 129, 0.3);
    padding: 2px 8px;
    border-radius: 4px;
    font-weight: 600;
    font-size: 11px;
    font-family: 'JetBrains Mono', monospace;
  }
  .badge-redact {
    background-color: rgba(245, 158, 11, 0.15);
    color: #fbbf24;
    border: 1px solid rgba(245, 158, 11, 0.3);
    padding: 2px 8px;
    border-radius: 4px;
    font-weight: 600;
    font-size: 11px;
    font-family: 'JetBrains Mono', monospace;
  }
  .badge-escalate {
    background-color: rgba(99, 102, 241, 0.15);
    color: #a5b4fc;
    border: 1px solid rgba(99, 102, 241, 0.3);
    padding: 2px 8px;
    border-radius: 4px;
    font-weight: 600;
    font-size: 11px;
    font-family: 'JetBrains Mono', monospace;
  }
  .badge-block {
    background-color: rgba(239, 68, 68, 0.15);
    color: #f87171;
    border: 1px solid rgba(239, 68, 68, 0.3);
    padding: 2px 8px;
    border-radius: 4px;
    font-weight: 600;
    font-size: 11px;
    font-family: 'JetBrains Mono', monospace;
  }

  /* Guide banner box */
  .guided-banner {
    background: linear-gradient(90deg, rgba(56, 189, 248, 0.08) 0%, rgba(99, 102, 241, 0.08) 100%);
    border: 1px solid rgba(56, 189, 248, 0.25);
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 20px;
    font-size: 13px;
    color: #cbd5e1;
    line-height: 1.6;
  }
</style>
""", unsafe_allow_html=True)

# Auto-initialize and seed DB on startup
try:
    from src.db.database import (
        DB_PATH, init_db, get_account, get_transactions, detect_structuring,
        get_pending_approvals, get_approval, update_approval_status,
        freeze_account, refund_transaction, create_approval
    )
    from src.db.audit import get_audit_log, verify_audit_chain, tamper_row, init_audit_table
    from src.security.session import DEMO_TOKENS, SessionRegistry
    from src.security.guardrails import (
        pre_check, post_process, compute_args_sha256, canonical_json
    )
    # Ensure directory and database are initialized
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    init_db()
    init_audit_table()
except Exception as e:
    st.error(f"Startup initialization error: {e}")
    st.stop()

# Header Area
col_h1, col_h2 = st.columns([3, 1])
with col_h1:
    st.title("🏦 Fintech Compliance Officer Workbench")
    st.caption("Institutional Zero-Trust AI Guardrails · Model Context Protocol (FastMCP) · SHA-256 Audit Chain")
with col_h2:
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
    <div style="text-align: right;">
      <span class="badge-allow">● SOC 2 / RBI INVARIANT READY</span>
    </div>
    """, unsafe_allow_html=True)

# Collapsible 60-Second Guided Demo Banner
with st.expander("⏱️ **60-Second Guided Demo: 3 Clicks to Test All Guardrails**", expanded=True):
    st.markdown("""
    <div class="guided-banner">
      <strong>Welcome to the Zero-Trust Compliance Console!</strong> Try these 3 self-contained tests:
      <ol style="margin-top: 6px; padding-left: 20px;">
        <li><strong>Verify PII Masking:</strong> In <strong>Tab 1</strong>, keep role as <code>junior_alice</code>, select <code>get_account_profile</code> for <code>ACC-001</code>, and click <strong>Run Tool</strong>. Notice how account numbers become <code>****4821</code> and PAN becomes <code>XXXXX234F</code> (Decision: <code>REDACT</code>). Switch role to <code>senior_carol</code> to see unmasked privileged access!</li>
        <li><strong>Four-Eyes HITL Control:</strong> In <strong>Tab 1</strong>, select <code>senior_carol</code> and run <code>request_account_freeze</code> for <code>ACC-010</code> to generate a 15-min approval gate. Then switch to <strong>Tab 2</strong> as <code>officer_eve</code> to inspect evidence and click <strong>Approve</strong>. (Attempting self-approval triggers an immediate <code>DUAL_CONTROL_VIOLATION</code>).</li>
        <li><strong>Cryptographic Tamper Lab:</strong> Go to <strong>Tab 3</strong> to view the live SHA-256 hash-chained ledger. Click <strong>Simulate Database Tampering</strong> to modify a historical row in SQLite and watch the verifier instantly pinpoint the exact corrupted row!</li>
      </ol>
    </div>
    """, unsafe_allow_html=True)

tab1, tab2, tab3 = st.tabs([
    "🛡️ Agent & Guardrail Simulator",
    "👁️ Four-Eyes Approval Queue",
    "🔐 Cryptographic Audit Ledger & Tamper Lab"
])

# ─── TAB 1: GUARDRAIL SIMULATOR ───────────────────────────────────────────────
with tab1:
    st.header("Live Agent & Guardrail Simulator")

    with st.sidebar:
        st.subheader("Zero-Trust Session")
        role_label = st.selectbox(
            "Active User / Identity",
            list(DEMO_TOKENS.keys()),
            index=0,
            help="Resolved strictly from server-side token registry — client cannot spoof actor_role"
        )
        session_token = DEMO_TOKENS[role_label]
        try:
            current_session = SessionRegistry.resolve(session_token)
            st.markdown(f"**Role:** `{current_session.actor_role}`")
            st.markdown(f"**Tenant ID:** `{current_session.tenant_id}`")
            st.markdown(f"**Session Sub:** `{current_session.sub}`")
            st.markdown(f"**Token:** `{session_token[:10]}...`")
        except Exception as e:
            st.error(str(e))

    tool_choice = st.selectbox("Select MCP Tool", [
        "get_account_profile",
        "query_transactions",
        "detect_structuring_anomalies",
        "request_account_freeze",
        "request_fee_refund",
        "execute_approved_action"
    ])

    # Dynamic argument inputs
    args_dict = {}
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
        tenant_id = st.selectbox("tenant_id", ["tenant_neobank_in", "tenant_b2b_cards"])
        threshold_cents = st.number_input("threshold_cents", value=999900, step=1000, help="Sub-threshold structuring limit (default ₹9,999 in paise)")
        args_dict = {"tenant_id": tenant_id, "threshold_cents": int(threshold_cents)}
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
        # Pre-check: RBAC validation
        try:
            session = pre_check(session_token, tool_choice, args_dict)
        except PermissionError as e:
            st.error(f"🚫 **RBAC BLOCK** — {e}")
            from src.db.audit import log_event
            log_event(role_label, "unknown", "unknown", tool_choice,
                      compute_args_sha256(tool_choice, args_dict, role_label), "BLOCK", str(e))
            st.stop()
        except ValueError as e:
            st.error(f"❌ **Session Error** — {e}")
            st.stop()

        args_sha256 = compute_args_sha256(tool_choice, args_dict, session.sub)

        # Execute the tool
        raw_result = None
        error = None
        try:
            if tool_choice == "get_account_profile":
                raw_result = get_account(args_dict.get("account_id"), session.tenant_id)
                if not raw_result:
                    error = "Account not found in your tenant scope"
            elif tool_choice == "query_transactions":
                raw_result = get_transactions(
                    args_dict.get("account_id"),
                    args_dict.get("start_date") or None,
                    args_dict.get("end_date") or None,
                    int(args_dict.get("limit", 20))
                )
            elif tool_choice == "detect_structuring_anomalies":
                raw_result = detect_structuring(
                    args_dict.get("tenant_id", "tenant_neobank_in"),
                    int(args_dict.get("threshold_cents", 999900))
                )
            elif tool_choice == "request_account_freeze":
                appr_id = str(uuid.uuid4())
                exp_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
                can_args = canonical_json(args_dict)
                create_approval(appr_id, session.sub, session.actor_role,
                                tool_choice, can_args, args_sha256, exp_at)
                raw_result = {"approval_id": appr_id, "expires_in_seconds": 900,
                              "status": "PENDING", "decision": "ESCALATE"}
                from src.db.audit import log_event
                log_event(session.sub, session.actor_role, session.tenant_id,
                          tool_choice, args_sha256, "ESCALATE", f"Created: {appr_id}")
                st.success("🔶 **Approval Gate Created!** Requires Compliance Officer Dual-Control")
                st.code(appr_id, language="text")
                st.info("💡 Copy this `approval_id` to approve it in **Tab 2** as `officer_eve`, or execute it with `execute_approved_action`.")
            elif tool_choice == "request_fee_refund":
                appr_id = str(uuid.uuid4())
                exp_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
                can_args = canonical_json(args_dict)
                create_approval(appr_id, session.sub, session.actor_role,
                                tool_choice, can_args, args_sha256, exp_at)
                raw_result = {"approval_id": appr_id, "expires_in_seconds": 900,
                              "status": "PENDING", "decision": "ESCALATE"}
                from src.db.audit import log_event
                log_event(session.sub, session.actor_role, session.tenant_id,
                          tool_choice, args_sha256, "ESCALATE", f"Created: {appr_id}")
                st.success("🔶 **Refund Approval Created!**")
                st.code(appr_id, language="text")
            elif tool_choice == "execute_approved_action":
                appr_id = args_dict.get("approval_id", "")
                approval = get_approval(appr_id)
                if not approval:
                    error = "Approval not found"
                elif approval["status"] != "PENDING":
                    error = f"ALREADY_{approval['status']}: approval cannot be executed"
                elif datetime.now(timezone.utc).isoformat() > approval["expires_at"]:
                    error = "EXPIRED: approval has passed its 15-minute TTL"
                elif approval["requester_sub"] == session.sub:
                    error = "DUAL_CONTROL_VIOLATION: compliance_officer cannot approve their own request"
                else:
                    orig_args = json.loads(approval["canonical_args_json"])
                    exp_sha = compute_args_sha256(approval["tool_name"], orig_args, approval["requester_sub"])
                    if exp_sha != approval["args_sha256"]:
                        error = "ARGUMENT_HASH_MISMATCH: approval binding invalid"
                    else:
                        update_approval_status(appr_id, "CONSUMED", session.sub,
                                               datetime.now(timezone.utc).isoformat())
                        if approval["tool_name"] == "request_account_freeze":
                            freeze_account(orig_args["account_id"])
                            raw_result = {"result": "Account frozen successfully", "account_id": orig_args["account_id"]}
                        elif approval["tool_name"] == "request_fee_refund":
                            new_id = refund_transaction(orig_args["transaction_id"], orig_args["amount_cents"])
                            raw_result = {"result": "Refund processed successfully", "new_txn_id": new_id}
                        from src.db.audit import log_event
                        log_event(session.sub, session.actor_role, session.tenant_id,
                                  tool_choice, args_sha256, "EXECUTED", f"Executed {approval['tool_name']}")
        except Exception as ex:
            error = str(ex)

        if error:
            st.error(f"🚫 **Action Blocked:** {error}")
        elif raw_result is not None and tool_choice not in ("request_account_freeze", "request_fee_refund"):
            processed = post_process(raw_result, session, tool_choice, args_sha256)
            from src.db.audit import log_event
            log_event(session.sub, session.actor_role, session.tenant_id,
                      tool_choice, args_sha256, processed["decision"])

            decision = processed["decision"]
            if decision == "ALLOW":
                st.markdown('<span class="badge-allow">● DECISION: ALLOW (Unmasked Privileged Output)</span>', unsafe_allow_html=True)
            elif decision == "REDACT":
                st.markdown('<span class="badge-redact">● DECISION: REDACT (PII Masked for Junior Analyst)</span>', unsafe_allow_html=True)
            else:
                st.markdown(f'<span class="badge-block">● DECISION: {decision}</span>', unsafe_allow_html=True)

            col_raw, col_guard = st.columns(2)
            with col_raw:
                st.subheader("📋 Raw Database Record")
                st.json(raw_result)
            with col_guard:
                st.subheader("🛡️ Guardrailed Agent Output")
                st.json(processed["data"])

            # Prompt injection warning check
            proc_str = json.dumps(processed["data"])
            if "[INJECTION STRIPPED]" in proc_str:
                st.warning("⚠️ **Prompt Injection Neutralized:** Adversarial instructions in the transaction memo were scrubbed before reaching the LLM context window.")


# ─── TAB 2: FOUR-EYES APPROVAL QUEUE ─────────────────────────────────────────
with tab2:
    st.header("👁️ Four-Eyes Approval Queue")
    st.markdown("State-mutating operations require independent approval from an authorized Compliance Officer.")

    co_label = st.selectbox("Acting Compliance Officer",
                            ["officer_eve", "officer_frank"],
                            help="Only compliance_officer roles have approval permissions")
    co_token = DEMO_TOKENS[co_label]
    try:
        co_session = SessionRegistry.resolve(co_token)
        st.info(f"**Authenticated Identity:** `{co_session.sub}` | **Role:** `{co_session.actor_role}` | **Tenant:** `{co_session.tenant_id}`")
    except Exception as e:
        st.error(str(e))
        st.stop()

    if st.button("🔄 Refresh Queue"):
        st.rerun()

    approvals = get_pending_approvals()

    if not approvals:
        st.info("📭 No pending approvals. Switch to Tab 1 as `senior_carol` to create an account freeze or refund request.")
    else:
        st.metric("Pending Approval Requests", len(approvals))
        for appr in approvals:
            appr_id = appr["approval_id"]
            with st.expander(f"🔶 [{appr['tool_name']}] · ID: {appr_id[:12]}... (Requested by: {appr['requester_sub']})"):
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown(f"**Requester Sub:** `{appr['requester_sub']}`")
                    st.markdown(f"**Requester Role:** `{appr['requester_role']}`")
                    st.markdown(f"**Created At (UTC):** {appr['created_at']}")
                    st.markdown(f"**Expires At (UTC):** {appr['expires_at']}")

                    if datetime.now(timezone.utc).isoformat() > appr["expires_at"]:
                        st.markdown('<span class="badge-block">⌛ STATUS: EXPIRED</span>', unsafe_allow_html=True)
                    else:
                        st.markdown('<span class="badge-escalate">● STATUS: AWAITING APPROVAL</span>', unsafe_allow_html=True)

                with c2:
                    st.markdown("**Bound Canonical Arguments:**")
                    try:
                        st.json(json.loads(appr["canonical_args_json"]))
                    except Exception:
                        st.code(appr["canonical_args_json"])

                # Strict Four-Eyes verification
                if co_session.actor_role != "compliance_officer":
                    st.warning("⚠️ Active role must be compliance_officer to approve.")
                elif appr["requester_sub"] == co_session.sub:
                    st.error("🔒 **DUAL_CONTROL_VIOLATION**: Four-Eyes invariant prohibits self-approval. A different officer must approve.")
                else:
                    b1, b2 = st.columns(2)
                    if b1.button("✅ Approve Request", key=f"appr_{appr_id}"):
                        update_approval_status(appr_id, "APPROVED", approver_sub=co_session.sub)
                        from src.db.audit import log_event
                        log_event(co_session.sub, co_session.actor_role, co_session.tenant_id,
                                  "approve_action", compute_args_sha256("approve_action", {"approval_id": appr_id}, co_session.sub),
                                  "ALLOW", f"Approved by {co_session.sub}")
                        st.success("✅ Request Approved! It can now be consumed via `execute_approved_action`.")
                        st.rerun()
                    if b2.button("❌ Reject Request", key=f"rej_{appr_id}"):
                        update_approval_status(appr_id, "REJECTED", approver_sub=co_session.sub)
                        from src.db.audit import log_event
                        log_event(co_session.sub, co_session.actor_role, co_session.tenant_id,
                                  "reject_action", compute_args_sha256("reject_action", {"approval_id": appr_id}, co_session.sub),
                                  "BLOCK", f"Rejected by {co_session.sub}")
                        st.error("❌ Request Rejected.")
                        st.rerun()


# ─── TAB 3: AUDIT LEDGER & TAMPER LAB ────────────────────────────────────────
with tab3:
    st.header("🔐 Cryptographic Audit Ledger & Tamper Lab")
    st.markdown(
        "Every event is chained with SHA-256 (`entry_hash = SHA256(prev_hash || timestamp || session || role || tool || args_sha256 || decision)`). "
        "This closes AgentGuard's documented limitation by making SQLite audit records mathematically tamper-evident."
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
        st.dataframe(df[avail], use_container_width=True, height=280)
        st.metric("Total Cryptographic Log Rows", len(logs))
    else:
        st.info("No audit logs yet. Run tools in Tab 1 to populate the ledger.")

    st.markdown("---")

    col_v, col_t = st.columns(2)

    with col_v:
        st.subheader("🔍 Cryptographic Chain Verifier")
        st.caption("Re-walks every link from GENESIS row #1 to the latest event.")
        if st.button("Verify Full Chain Integrity", type="primary"):
            res = verify_audit_chain()
            if res["ok"]:
                st.success("✅ **CHAIN INTACT:** 100% of SHA-256 links verified against genesis root.")
            else:
                st.error(
                    f"❌ **TAMPER DETECTED:** Chain broken at `event_id = {res.get('corrupted_event_id')}`!\n\n"
                    f"**Cryptographic Proof:** {res.get('reason')}"
                )

    with col_t:
        st.subheader("🧪 Live Tamper Lab")
        st.caption("Simulates an unauthorized SQLite database row modification.")
        if st.button("💥 Simulate Database Tampering", type="secondary"):
            if logs:
                target_id = logs[0]["event_id"]
                curr_dec = logs[0]["decision"]
                tampered_dec = "ALLOW" if curr_dec != "ALLOW" else "BLOCK"
                tamper_row(target_id, tampered_dec)
                st.warning(f"🔧 Direct SQLite update executed: Modified `event_id={target_id}` decision to `{tampered_dec}` without updating SHA-256 hashes.")

                check = verify_audit_chain()
                if not check["ok"]:
                    st.error(f"🔒 **VERIFIER CAUGHT TAMPERING!** Broken link detected at `event_id = {check.get('corrupted_event_id')}`.")
                else:
                    st.error("Verifier failed to detect tampering.")
            else:
                st.warning("Generate events in Tab 1 first.")

        if st.button("🔄 Restore Chain to Valid State"):
            if logs:
                target_id = logs[0]["event_id"]
                orig_dec = logs[0]["decision"]
                tamper_row(target_id, orig_dec)
                check = verify_audit_chain()
                if check["ok"]:
                    st.success("✅ Chain restored and verified!")
                else:
                    st.info("Chain reset complete.")
                st.rerun()

    with st.expander("🔎 View Full Cryptographic Payload"):
        if logs:
            st.dataframe(pd.DataFrame(logs), use_container_width=True)
