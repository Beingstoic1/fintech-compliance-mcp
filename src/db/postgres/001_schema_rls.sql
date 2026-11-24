-- fintech-compliance-mcp: Postgres schema with row-level security (T10).
--
-- Run once, as a superuser or migration role (it creates roles and sets ownership):
--   psql "$ADMIN_DSN" -v ON_ERROR_STOP=1 -f src/db/postgres/001_schema_rls.sql
--
-- Roles (all NOLOGIN group roles; deployments create LOGIN members, e.g.
--   CREATE ROLE fintech_app_login LOGIN PASSWORD '<from secrets manager>' IN ROLE fintech_app;):
--   fintech_owner    owns every object. Never used by the application.
--   fintech_app      the MCP server / Workbench. Not owner, NOBYPASSRLS. Sees exactly the
--                    rows of the tenant set by `SELECT set_config('app.tenant_id', $1, true)`
--                    at the start of each transaction (src/db/postgres/session.py).
--                    With no tenant set, every tenant policy evaluates to NULL: zero rows.
--   fintech_auditor  read-only, cross-tenant, audit tables only (chain verifier).
--
-- Defense layers: RLS (row visibility), column-level GRANTs (what may change),
-- composite (id, tenant_id) foreign keys (no cross-tenant references, even for the
-- owner), and triggers (approval state machine; append-only, gap-free audit chain).
-- FORCE ROW LEVEL SECURITY makes the owner subject to policies too.

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'fintech_owner') THEN
        CREATE ROLE fintech_owner NOLOGIN NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'fintech_app') THEN
        CREATE ROLE fintech_app NOLOGIN NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'fintech_auditor') THEN
        CREATE ROLE fintech_auditor NOLOGIN NOBYPASSRLS;
    END IF;
END
$$;

CREATE SCHEMA IF NOT EXISTS fintech AUTHORIZATION fintech_owner;
REVOKE ALL ON SCHEMA fintech FROM PUBLIC;
GRANT USAGE ON SCHEMA fintech TO fintech_app, fintech_auditor;

SET LOCAL ROLE fintech_owner;           -- everything below is owned by fintech_owner
SET LOCAL search_path = fintech, pg_catalog;

-- ─── tenant context ─────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION fintech.current_tenant() RETURNS text
    LANGUAGE sql STABLE
AS $$ SELECT NULLIF(current_setting('app.tenant_id', true), '') $$;

-- ─── business tables ────────────────────────────────────────────────────────

CREATE TABLE fintech.tenants (
    tenant_id   text PRIMARY KEY CHECK (tenant_id ~ '^[a-z0-9_]{3,64}$'),
    name        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE fintech.accounts (
    account_id      text PRIMARY KEY CHECK (account_id ~ '^ACC-[0-9]{3,12}$'),
    tenant_id       text NOT NULL REFERENCES fintech.tenants (tenant_id),
    holder_name     text NOT NULL,
    account_number  text NOT NULL,
    pan_last4       text CHECK (pan_last4 ~ '^[0-9]{4}$'),
    tax_id          text,
    account_type    text NOT NULL,
    kyc_status      text NOT NULL DEFAULT 'verified',
    risk_score      numeric(5,4) NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 1),
    is_frozen       boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, tenant_id)
);

CREATE TABLE fintech.transactions (
    txn_id            text PRIMARY KEY CHECK (txn_id ~ '^TXN-[A-Z0-9-]{1,40}$'),
    tenant_id         text NOT NULL,
    account_id        text NOT NULL,
    merchant_id       text,
    amount_cents      bigint NOT NULL CHECK (amount_cents > 0),
    currency          char(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    txn_type          text NOT NULL CHECK (txn_type IN ('debit', 'credit', 'refund')),
    status            text NOT NULL,
    memo              text,
    created_at        timestamptz NOT NULL DEFAULT now(),
    refund_of_txn_id  text,
    UNIQUE (txn_id, tenant_id),
    -- Composite FKs: a transaction (and a refund's original) must live in the same tenant.
    FOREIGN KEY (account_id, tenant_id) REFERENCES fintech.accounts (account_id, tenant_id),
    FOREIGN KEY (refund_of_txn_id, tenant_id) REFERENCES fintech.transactions (txn_id, tenant_id),
    CHECK ((txn_type = 'refund') = (refund_of_txn_id IS NOT NULL))
);
CREATE INDEX transactions_tenant_account_created ON fintech.transactions (tenant_id, account_id, created_at DESC);
CREATE INDEX transactions_refund_of ON fintech.transactions (tenant_id, refund_of_txn_id) WHERE refund_of_txn_id IS NOT NULL;

CREATE TABLE fintech.kyc_records (
    kyc_id               text PRIMARY KEY,
    tenant_id            text NOT NULL,      -- denormalised from accounts so RLS needs no join
    account_id           text NOT NULL,
    document_type        text NOT NULL,
    verification_status  text NOT NULL,
    verified_at          timestamptz,
    expiry_date          date,
    FOREIGN KEY (account_id, tenant_id) REFERENCES fintech.accounts (account_id, tenant_id)
);

CREATE TABLE fintech.compliance_alerts (
    alert_id     text PRIMARY KEY,
    tenant_id    text NOT NULL,
    account_id   text NOT NULL,
    alert_type   text NOT NULL,
    severity     text NOT NULL,
    description  text,
    is_resolved  boolean NOT NULL DEFAULT false,
    created_at   timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (account_id, tenant_id) REFERENCES fintech.accounts (account_id, tenant_id)
);

-- ─── Four-Eyes approvals (mirrors src/db/approvals.py) ──────────────────────

CREATE TABLE fintech.pending_approvals (
    approval_id                uuid PRIMARY KEY,
    tenant_id                  text NOT NULL REFERENCES fintech.tenants (tenant_id),
    requester_sub              text NOT NULL,
    requester_role             text NOT NULL,
    tool_name                  text NOT NULL CHECK (tool_name IN ('request_account_freeze', 'request_fee_refund')),
    canonical_args_json        jsonb NOT NULL,
    key_id                     text NOT NULL,
    args_digest                text NOT NULL,
    status                     text NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'APPROVED', 'CONSUMED', 'REJECTED', 'EXPIRED')),
    idempotency_key            text,
    created_at                 timestamptz NOT NULL,
    expires_at                 timestamptz NOT NULL,
    approver_sub               text,
    approved_at                timestamptz,
    approved_amr               jsonb,
    rejected_by_sub            text,
    rejected_at                timestamptz,
    rejection_reason           text CHECK (length(rejection_reason) <= 500),
    executed_by_sub            text,
    consumed_at                timestamptz,
    execution_idempotency_key  text,
    execution_result_json      jsonb,
    CHECK (expires_at > created_at),
    CHECK (approver_sub IS NULL OR approver_sub <> requester_sub),
    CHECK (status <> 'APPROVED' OR (approver_sub IS NOT NULL AND approved_at IS NOT NULL)),
    CHECK (status <> 'CONSUMED' OR (approver_sub IS NOT NULL AND executed_by_sub IS NOT NULL)),
    UNIQUE (tenant_id, requester_sub, idempotency_key)
);
CREATE INDEX pending_approvals_tenant_status ON fintech.pending_approvals (tenant_id, status, expires_at);

CREATE OR REPLACE FUNCTION fintech.pending_approvals_guard() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'APPROVAL_ROW_IMMUTABLE' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    -- A row is born PENDING with no decision columns: the app's INSERT grant covers
    -- every column, so without this a compromised app could insert an APPROVED row.
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'PENDING' OR num_nonnulls(
               NEW.approver_sub, NEW.approved_at, NEW.approved_amr, NEW.rejected_by_sub,
               NEW.rejected_at, NEW.rejection_reason, NEW.executed_by_sub, NEW.consumed_at,
               NEW.execution_idempotency_key, NEW.execution_result_json) > 0 THEN
            RAISE EXCEPTION 'ILLEGAL_APPROVAL_INSERT' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    IF NOT ((OLD.status = 'PENDING'  AND NEW.status IN ('APPROVED', 'REJECTED', 'EXPIRED'))
         OR (OLD.status = 'APPROVED' AND NEW.status IN ('CONSUMED', 'REJECTED', 'EXPIRED'))) THEN
        RAISE EXCEPTION 'ILLEGAL_APPROVAL_TRANSITION' USING ERRCODE = 'check_violation';
    END IF;
    IF (NEW.approval_id, NEW.tenant_id, NEW.requester_sub, NEW.requester_role, NEW.tool_name,
        NEW.canonical_args_json, NEW.key_id, NEW.args_digest, NEW.idempotency_key,
        NEW.created_at, NEW.expires_at)
       IS DISTINCT FROM
       (OLD.approval_id, OLD.tenant_id, OLD.requester_sub, OLD.requester_role, OLD.tool_name,
        OLD.canonical_args_json, OLD.key_id, OLD.args_digest, OLD.idempotency_key,
        OLD.created_at, OLD.expires_at) THEN
        RAISE EXCEPTION 'APPROVAL_ROW_IMMUTABLE' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER pending_approvals_guard
    BEFORE INSERT OR UPDATE OR DELETE ON fintech.pending_approvals
    FOR EACH ROW EXECUTE FUNCTION fintech.pending_approvals_guard();

-- ─── audit ledger (mirrors src/db/audit.py v2) ──────────────────────────────

CREATE TABLE fintech.audit_meta (
    k  text PRIMARY KEY,
    v  text NOT NULL
);
INSERT INTO fintech.audit_meta (k, v) VALUES ('genesis', 'GENESIS') ON CONFLICT (k) DO NOTHING;

CREATE TABLE fintech.audit_logs (
    event_id       bigint PRIMARY KEY CHECK (event_id >= 1),   -- assigned under the chain lock
    timestamp_utc  text NOT NULL,      -- exact string inside the HMAC preimage; never re-rendered
    session_sub    text NOT NULL,
    actor_role     text NOT NULL,
    tenant_id      text NOT NULL,      -- no FK: pre-auth rows use the sentinel 'unknown'
    tool_name      text NOT NULL,
    args_digest    text NOT NULL,
    decision       text NOT NULL CHECK (decision IN
        ('ALLOW', 'APPROVED', 'BLOCK', 'ERROR', 'ESCALATE', 'EXECUTED', 'EXPIRED', 'REDACT', 'REJECTED')),
    detail         text CHECK (detail IS NULL OR length(detail) <= 512),
    key_id         text NOT NULL,
    prev_hash      text NOT NULL,
    entry_hash     text NOT NULL CHECK (entry_hash ~ '^[0-9a-f]{64}$')
);
CREATE INDEX audit_logs_tenant_event ON fintech.audit_logs (tenant_id, event_id);

-- The chain is global (one head across tenants), but fintech_app can only see its own
-- tenant's rows. These SECURITY DEFINER functions expose the head *hash* only, under a
-- transaction-scoped advisory lock that serialises appends.
CREATE OR REPLACE FUNCTION fintech._audit_head(OUT event_id bigint, OUT entry_hash text)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = fintech, pg_catalog
AS $$
BEGIN
    SELECT a.event_id, a.entry_hash INTO event_id, entry_hash
      FROM fintech.audit_logs a ORDER BY a.event_id DESC LIMIT 1;
    IF NOT FOUND THEN
        event_id := 0;
        SELECT m.v INTO entry_hash FROM fintech.audit_meta m WHERE m.k = 'genesis';
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION fintech.audit_lock_head(OUT event_id bigint, OUT entry_hash text)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = fintech, pg_catalog
AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('fintech.audit_logs'));
    SELECT h.event_id, h.entry_hash INTO event_id, entry_hash FROM fintech._audit_head() h;
END
$$;

-- DB-enforced linkage: a row must be exactly head+1 and point at the head hash.
CREATE OR REPLACE FUNCTION fintech.audit_logs_link_guard() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = fintech, pg_catalog
AS $$
DECLARE
    head record;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('fintech.audit_logs'));
    SELECT * INTO head FROM fintech._audit_head();
    IF NEW.event_id <> head.event_id + 1 OR NEW.prev_hash IS DISTINCT FROM head.entry_hash THEN
        RAISE EXCEPTION 'AUDIT_CHAIN_LINK_INVALID' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION fintech.audit_append_only() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'AUDIT_LOG_APPEND_ONLY' USING ERRCODE = 'insufficient_privilege';
END
$$;

CREATE TRIGGER audit_logs_link_guard BEFORE INSERT ON fintech.audit_logs
    FOR EACH ROW EXECUTE FUNCTION fintech.audit_logs_link_guard();
CREATE TRIGGER audit_logs_no_mutation BEFORE UPDATE OR DELETE ON fintech.audit_logs
    FOR EACH ROW EXECUTE FUNCTION fintech.audit_append_only();
CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON fintech.audit_logs
    FOR EACH STATEMENT EXECUTE FUNCTION fintech.audit_append_only();
CREATE TRIGGER audit_meta_no_mutation BEFORE UPDATE OR DELETE ON fintech.audit_meta
    FOR EACH ROW EXECUTE FUNCTION fintech.audit_append_only();
CREATE TRIGGER audit_meta_no_truncate BEFORE TRUNCATE ON fintech.audit_meta
    FOR EACH STATEMENT EXECUTE FUNCTION fintech.audit_append_only();

-- ─── row-level security ─────────────────────────────────────────────────────

ALTER TABLE fintech.tenants            ENABLE ROW LEVEL SECURITY;
ALTER TABLE fintech.tenants            FORCE  ROW LEVEL SECURITY;
ALTER TABLE fintech.accounts           ENABLE ROW LEVEL SECURITY;
ALTER TABLE fintech.accounts           FORCE  ROW LEVEL SECURITY;
ALTER TABLE fintech.transactions       ENABLE ROW LEVEL SECURITY;
ALTER TABLE fintech.transactions       FORCE  ROW LEVEL SECURITY;
ALTER TABLE fintech.kyc_records        ENABLE ROW LEVEL SECURITY;
ALTER TABLE fintech.kyc_records        FORCE  ROW LEVEL SECURITY;
ALTER TABLE fintech.compliance_alerts  ENABLE ROW LEVEL SECURITY;
ALTER TABLE fintech.compliance_alerts  FORCE  ROW LEVEL SECURITY;
ALTER TABLE fintech.pending_approvals  ENABLE ROW LEVEL SECURITY;
ALTER TABLE fintech.pending_approvals  FORCE  ROW LEVEL SECURITY;
ALTER TABLE fintech.audit_logs         ENABLE ROW LEVEL SECURITY;
ALTER TABLE fintech.audit_logs         FORCE  ROW LEVEL SECURITY;
ALTER TABLE fintech.audit_meta         ENABLE ROW LEVEL SECURITY;
ALTER TABLE fintech.audit_meta         FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON fintech.tenants FOR SELECT TO fintech_app
    USING (tenant_id = fintech.current_tenant());
CREATE POLICY tenant_isolation ON fintech.accounts FOR ALL TO fintech_app
    USING (tenant_id = fintech.current_tenant()) WITH CHECK (tenant_id = fintech.current_tenant());
CREATE POLICY tenant_isolation ON fintech.transactions FOR ALL TO fintech_app
    USING (tenant_id = fintech.current_tenant()) WITH CHECK (tenant_id = fintech.current_tenant());
CREATE POLICY tenant_isolation ON fintech.kyc_records FOR ALL TO fintech_app
    USING (tenant_id = fintech.current_tenant()) WITH CHECK (tenant_id = fintech.current_tenant());
CREATE POLICY tenant_isolation ON fintech.compliance_alerts FOR ALL TO fintech_app
    USING (tenant_id = fintech.current_tenant()) WITH CHECK (tenant_id = fintech.current_tenant());
CREATE POLICY tenant_isolation ON fintech.pending_approvals FOR ALL TO fintech_app
    USING (tenant_id = fintech.current_tenant()) WITH CHECK (tenant_id = fintech.current_tenant());

CREATE POLICY tenant_read ON fintech.audit_logs FOR SELECT TO fintech_app
    USING (tenant_id = fintech.current_tenant());
CREATE POLICY tenant_append ON fintech.audit_logs FOR INSERT TO fintech_app
    WITH CHECK (tenant_id = fintech.current_tenant());
CREATE POLICY auditor_read ON fintech.audit_logs FOR SELECT TO fintech_auditor USING (true);
CREATE POLICY auditor_read ON fintech.audit_meta FOR SELECT TO fintech_auditor USING (true);
-- The owner sees the chain only so its SECURITY DEFINER head functions work.
CREATE POLICY owner_head_read ON fintech.audit_logs FOR SELECT TO fintech_owner USING (true);
CREATE POLICY owner_head_read ON fintech.audit_meta FOR SELECT TO fintech_owner USING (true);

-- ─── privileges (least privilege; nothing for PUBLIC) ───────────────────────

REVOKE ALL ON ALL TABLES IN SCHEMA fintech FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA fintech FROM PUBLIC;

GRANT SELECT                       ON fintech.tenants           TO fintech_app;
GRANT SELECT, UPDATE (is_frozen)   ON fintech.accounts          TO fintech_app;
GRANT SELECT, INSERT               ON fintech.transactions      TO fintech_app;
GRANT SELECT                       ON fintech.kyc_records       TO fintech_app;
GRANT SELECT                       ON fintech.compliance_alerts TO fintech_app;
GRANT SELECT, INSERT, UPDATE (status, approver_sub, approved_at, approved_amr, rejected_by_sub,
                              rejected_at, rejection_reason, executed_by_sub, consumed_at,
                              execution_idempotency_key, execution_result_json)
                                   ON fintech.pending_approvals TO fintech_app;
GRANT SELECT, INSERT               ON fintech.audit_logs        TO fintech_app;   -- never UPDATE/DELETE/TRUNCATE
GRANT SELECT                       ON fintech.audit_logs        TO fintech_auditor;
GRANT SELECT                       ON fintech.audit_meta        TO fintech_auditor;

GRANT EXECUTE ON FUNCTION fintech.current_tenant()  TO fintech_app, fintech_auditor;
GRANT EXECUTE ON FUNCTION fintech.audit_lock_head() TO fintech_app;

COMMIT;
