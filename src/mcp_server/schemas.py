"""Strict boundary types for every MCP tool (T05).

The same Annotated types are used in the tool signatures (so the MCP SDK rejects
malformed calls before the handler runs, and the advertised JSON schema carries the
bounds) and in the per-tool models below (re-validated in the handler for in-process
callers, failing closed with BLOCK + audit). Identity fields (user_id, role,
tenant_id) are deliberately absent: models forbid extras, and the SDK drops unknown
top-level keys before the handler, so they can never be trusted.
"""
from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

AccountId = Annotated[str, StringConstraints(strict=True, pattern=r"^ACC-[0-9]{3,12}$")]
TransactionId = Annotated[str, StringConstraints(strict=True, pattern=r"^TXN-[A-Z0-9-]{1,40}$")]
ApprovalId = Annotated[str, StringConstraints(
    strict=True, pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")]
Reason = Annotated[str, StringConstraints(strict=True, min_length=3, max_length=500, strip_whitespace=True)]
DateBound = Annotated[str, StringConstraints(
    strict=True, pattern=r"^(|\d{4}-\d{2}-\d{2}( \d{2}:\d{2}:\d{2})?)$")]
IdempotencyKey = Annotated[str, StringConstraints(strict=True, pattern=r"^[A-Za-z0-9_-]{8,64}$")]
QueryLimit = Annotated[int, Field(strict=True, ge=1, le=100)]
ThresholdCents = Annotated[int, Field(strict=True, ge=1, le=10**10)]
AmountCents = Annotated[int, Field(strict=True, ge=1, le=10**12)]


class _Strict(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class GetAccountProfileInput(_Strict):
    account_id: AccountId


class QueryTransactionsInput(_Strict):
    account_id: AccountId
    start_date: DateBound = ""
    end_date: DateBound = ""
    limit: QueryLimit = 50


class DetectStructuringInput(_Strict):
    threshold_cents: ThresholdCents = 999900


class RequestAccountFreezeInput(_Strict):
    account_id: AccountId
    reason: Reason
    idempotency_key: IdempotencyKey | None = None


class RequestFeeRefundInput(_Strict):
    transaction_id: TransactionId
    amount_cents: AmountCents
    reason: Reason
    idempotency_key: IdempotencyKey | None = None


class ExecuteApprovedActionInput(_Strict):
    approval_id: ApprovalId
    idempotency_key: IdempotencyKey | None = None


class RejectApprovedActionInput(_Strict):
    approval_id: ApprovalId
    reason: Reason


TOOL_INPUTS: dict[str, type[_Strict]] = {
    "get_account_profile": GetAccountProfileInput,
    "query_transactions": QueryTransactionsInput,
    "detect_structuring_anomalies": DetectStructuringInput,
    "request_account_freeze": RequestAccountFreezeInput,
    "request_fee_refund": RequestFeeRefundInput,
    "execute_approved_action": ExecuteApprovedActionInput,
    "reject_approved_action": RejectApprovedActionInput,
}
