"""
Fintech Compliance Officer Workbench — Streamlit App
3-tab interactive UI: Guardrail Simulator | Approval Queue | Audit Ledger & Tamper Lab
"""
import json
import uuid
from datetime import datetime, timedelta, timezone

import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="Fintech Compliance Workbench",
    page_icon="🏦",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize DB on startup
try:
    from src.db.database import (
        init_db, get_account, get_transactions, detect_structuring,
        get_pending_approvals, get_approval, update_approval_status,
        freeze_account, refund_transaction, create_approval
    )
    from src.db.audit import get_audit_log, verify_audit_chain, tamper_row, init_audit_table
    from src.security.session import DEMO_TOKENS, SessionRegistry
    from src.security.guardrails import (
        pre_check, post_process, compute_args_sha256, canonical_json
    )
    init_db()
    init_audit_table()
except Exception as e:
    st.error(f"Startup error: {e}")
    st.stop()

st.title("🏦 Fintech Compliance Officer Workbench")
st.caption("Zero-trust MCP system · SHA-256 hash-chained audit · Four-Eyes approval gate")

tab1, tab2, tab3 = st.tabs([
    "🛡️ Agent & Guardrail Simulator",
    "👁️ Four-Eyes Approval Queue",
    "🔐 Cryptographic Audit Ledger & Tamper Lab"
])

# ─── TAB 1: GUARDRAIL SIMULATOR ───────────────────────────────────────────────
with tab1:
    st.header("Live Agent & Guardrail Simulator")

    with st.sidebar:
        st.subheader("Session Controls")
        role_label = st.selectbox(
            "Active User / Role",
            list(DEMO_TOKENS.keys()),
            index=0,
            help="Role is resolved from server-side session registry — not from args"
        )
        session_token = DEMO_TOKENS[role_label]
        try:
            current_session = SessionRegistry.resolve(session_token)
            st.info(f"**Role:** `{current_session.actor_role}`\n\n**Tenant:** `{current_session.tenant_id}`")
        except Exception as e:
            st.error(str(e))

    tool_choice = st.selectbox("MCP Tool", [
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
        account_id = st.text_input("account_id", value="ACC-001")
        args_dict = {"account_id": account_id}
    elif tool_choice == "query_transactions":
        c1, c2, c3, c4 = st.columns(4)
        account_id = c1.text_input("account_id", value="ACC-001")
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
        threshold_cents = st.number_input("threshold_cents", value=999900, step=1000)
        args_dict = {"tenant_id": tenant_id, "threshold_cents": int(threshold_cents)}
    elif tool_choice == "request_account_freeze":
        account_id = st.text_input("account_id", value="ACC-010")
        reason = st.text_area("reason", value="Suspected structuring activity")
        args_dict = {"account_id": account_id, "reason": reason}
    elif tool_choice == "request_fee_refund":
        c1, c2 = st.columns(2)
        txn_id = c1.text_input("transaction_id", value="TXN-001")
        amount = c2.number_input("amount_cents", min_value=1, value=50000)
        reason = st.text_area("reason", value="Fee charged in error")
        args_dict = {"transaction_id": txn_id, "amount_cents": int(amount), "reason": reason}
    elif tool_choice == "execute_approved_action":
        approval_id = st.text_input("approval_id", value="")
        args_dict = {"approval_id": approval_id}

    if st.button("▶️ Run Tool", type="primary"):
        # Pre-check
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
                    error = "Account not found"
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
                st.success(f"🔶 Approval created!")
                st.code(appr_id, language="text")
                st.info("Copy this approval_id and use it in Tab 2 (or execute_approved_action tool) as a compliance_officer.")
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
                st.success(f"🔶 Refund approval created!")
                st.code(appr_id, language="text")
            elif tool_choice == "execute_approved_action":
                appr_id = args_dict.get("approval_id", "")
                approval = get_approval(appr_id)
                if not approval:
                    error = "Approval not found"
                elif approval["status"] != "PENDING":
                    error = f"ALREADY_{approval['status']}"
                elif datetime.now(timezone.utc).isoformat() > approval["expires_at"]:
                    error = "EXPIRED"
                elif approval["requester_sub"] == session.sub:
                    error = "DUAL_CONTROL_VIOLATION: Cannot approve your own request"
                else:
                    orig_args = json.loads(approval["canonical_args_json"])
                    exp_sha = compute_args_sha256(approval["tool_name"], orig_args, approval["requester_sub"])
                    if exp_sha != approval["args_sha256"]:
                        error = "ARGUMENT_HASH_MISMATCH"
                    else:
                        update_approval_status(appr_id, "CONSUMED", session.sub,
                                               datetime.now(timezone.utc).isoformat())
                        if approval["tool_name"] == "request_account_freeze":
                            freeze_account(orig_args["account_id"])
                            raw_result = {"result": "Account frozen", "account_id": orig_args["account_id"]}
                        elif approval["tool_name"] == "request_fee_refund":
                            new_id = refund_transaction(orig_args["transaction_id"], orig_args["amount_cents"])
                            raw_result = {"result": "Refund processed", "new_txn_id": new_id}
                        from src.db.audit import log_event
                        log_event(session.sub, session.actor_role, session.tenant_id,
                                  tool_choice, args_sha256, "EXECUTED", f"Executed {approval['tool_name']}")
        except Exception as ex:
            error = str(ex)

        if error:
            st.error(f"🚫 **Error:** {error}")
        elif raw_result is not None and tool_choice not in ("request_account_freeze", "request_fee_refund"):
            processed = post_process(raw_result, session, tool_choice, args_sha256)
            from src.db.audit import log_event
            log_event(session.sub, session.actor_role, session.tenant_id,
                      tool_choice, args_sha256, processed["decision"])

            # Decision badge
            decision = processed["decision"]
            if decision == "ALLOW":
                st.success("✅ Decision: ALLOW")
            elif decision == "REDACT":
                st.warning("🔶 Decision: REDACT — PII masked for your role")
            else:
                st.error(f"🚫 Decision: {decision}")

            # Side-by-side raw vs guardrailed
            col_raw, col_guard = st.columns(2)
            with col_raw:
                st.subheader("📋 Raw DB Output")
                st.json(raw_result)
            with col_guard:
                st.subheader("🛡️ Guardrailed Output (what client sees)")
                st.json(processed["data"])

            # Injection warning
            if decision == "REDACT":
                raw_str = json.dumps(raw_result)
                proc_str = json.dumps(processed["data"])
                if "[INJECTION STRIPPED]" in proc_str:
                    st.warning("⚠️ **Prompt injection detected and neutralized** — memo field contained injection attempt.")


# ─── TAB 2: FOUR-EYES APPROVAL QUEUE ─────────────────────────────────────────
with tab2:
    st.header("👁️ Four-Eyes Approval Queue")

    co_label = st.selectbox("Acting As (Approving Officer)",
                             ["officer_eve", "officer_frank"],
                             help="Only compliance_officers can approve/reject")
    co_token = DEMO_TOKENS[co_label]
    try:
        co_session = SessionRegistry.resolve(co_token)
        st.info(f"**Role:** `{co_session.actor_role}` | **Tenant:** `{co_session.tenant_id}`")
    except Exception as e:
        st.error(str(e))
        st.stop()

    if st.button("🔄 Refresh Queue"):
        st.rerun()

    approvals = get_pending_approvals()

    if not approvals:
        st.info("📭 No pending approvals. Use Tab 1 as `senior_carol` or `senior_dave` to request account freezes or refunds.")
    else:
        st.metric("Pending Requests", len(approvals))
        for appr in approvals:
            appr_id = appr["approval_id"]
            with st.expander(f"🔶 [{appr['tool_name']}] — `{appr_id[:12]}...` | Requested by: {appr['requester_sub']}"):
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown(f"**Requester:** `{appr['requester_sub']}`")
                    st.markdown(f"**Role:** `{appr['requester_role']}`")
                    st.markdown(f"**Created:** {appr['created_at']}")
                    st.markdown(f"**Expires:** {appr['expires_at']}")

                    # Expiry check
                    if datetime.now(timezone.utc).isoformat() > appr["expires_at"]:
                        st.error("⌛ EXPIRED")
                    else:
                        st.success("✅ Valid")

                with c2:
                    st.markdown("**Arguments:**")
                    try:
                        st.json(json.loads(appr["canonical_args_json"]))
                    except Exception:
                        st.code(appr["canonical_args_json"])

                # Four-eyes logic
                if co_session.actor_role != "compliance_officer":
                    st.warning("⚠️ Switch to a compliance_officer role to approve/reject.")
                elif appr["requester_sub"] == co_session.sub:
                    st.error("🔒 **DUAL_CONTROL_VIOLATION**: You cannot approve your own request.")
                else:
                    btn1, btn2 = st.columns(2)
                    if btn1.button("✅ Approve", key=f"approve_{appr_id}"):
                        update_approval_status(appr_id, "APPROVED", approver_sub=co_session.sub)
                        from src.db.audit import log_event
                        log_event(co_session.sub, co_session.actor_role, co_session.tenant_id,
                                  "approve_action", compute_args_sha256("approve_action",
                                  {"approval_id": appr_id}, co_session.sub), "ALLOW",
                                  f"Approved by {co_session.sub}")
                        st.success("✅ Approved! Use `execute_approved_action` in Tab 1 to execute.")
                        st.rerun()
                    if btn2.button("❌ Reject", key=f"reject_{appr_id}"):
                        update_approval_status(appr_id, "REJECTED", approver_sub=co_session.sub)
                        from src.db.audit import log_event
                        log_event(co_session.sub, co_session.actor_role, co_session.tenant_id,
                                  "reject_action", compute_args_sha256("reject_action",
                                  {"approval_id": appr_id}, co_session.sub), "BLOCK",
                                  f"Rejected by {co_session.sub}")
                        st.error("❌ Request rejected.")
                        st.rerun()


# ─── TAB 3: AUDIT LEDGER & TAMPER LAB ────────────────────────────────────────
with tab3:
    st.header("🔐 Cryptographic Audit Ledger & Tamper Lab")
    st.markdown(
        "Every tool call is recorded in a **SHA-256 hash-chained ledger**. "
        "Each row's `entry_hash` is computed from the previous row's hash — "
        "any modification is cryptographically detectable."
    )

    # Live ledger
    logs = get_audit_log(limit=200)
    if logs:
        df = pd.DataFrame(logs)
        df["prev_hash_short"]  = df["prev_hash"].str[:16] + "..."
        df["entry_hash_short"] = df["entry_hash"].str[:16] + "..."

        display_cols = ["event_id", "timestamp_utc", "session_sub", "actor_role",
                        "tenant_id", "tool_name", "decision",
                        "prev_hash_short", "entry_hash_short"]
        available = [c for c in display_cols if c in df.columns]
        st.dataframe(df[available], use_container_width=True, height=300)
        st.metric("Total Audit Events", len(logs))
    else:
        st.info("No audit events yet — run some tools in Tab 1.")

    st.markdown("---")

    # Chain verification
    col_verify, col_tamper = st.columns(2)

    with col_verify:
        st.subheader("🔍 Chain Verification")
        if st.button("Verify Chain Integrity", type="primary"):
            result = verify_audit_chain()
            if result["ok"]:
                st.success("✅ **CHAIN INTACT** — All SHA-256 links verified end-to-end.")
            else:
                st.error(
                    f"❌ **CHAIN BROKEN** at `event_id = {result.get('corrupted_event_id')}`\n\n"
                    f"Reason: {result.get('reason', 'Hash mismatch')}"
                )

    with col_tamper:
        st.subheader("🧪 Tamper Lab")
        st.warning("**Demo only:** Simulates a bad actor modifying the audit database directly.")
        if st.button("💥 Simulate Database Tampering", type="secondary"):
            if logs:
                target_id = logs[0]["event_id"]
                old_decision = logs[0]["decision"]
                # Flip the decision without updating hashes
                new_decision = "ALLOW" if old_decision != "ALLOW" else "BLOCK"
                tamper_row(target_id, new_decision)
                st.info(
                    f"🔧 Tampered `event_id={target_id}`: "
                    f"changed `decision` from `{old_decision}` → `{new_decision}` "
                    f"**without updating hash chain**."
                )
                result = verify_audit_chain()
                if not result["ok"]:
                    st.error(
                        f"🔒 **TAMPER DETECTED** by SHA-256 verifier at "
                        f"`event_id = {result.get('corrupted_event_id')}`\n\n"
                        f"{result.get('reason', 'entry_hash mismatch')}"
                    )
                else:
                    st.error("⚠️ Verifier did not catch the tampering — this is a bug.")
            else:
                st.warning("Run some tools in Tab 1 first to generate audit log entries.")

    # Full hash chain view
    with st.expander("🔎 View Full Hash Chain (all columns)"):
        if logs:
            st.dataframe(pd.DataFrame(logs), use_container_width=True)
        else:
            st.write("No entries yet.")
