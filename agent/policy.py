"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_PATH = Path(__file__).resolve().parent.parent / "data" / "principals.json"


def _load_principals() -> dict:
    if PRINCIPALS_PATH.exists():
        return json.loads(PRINCIPALS_PATH.read_text(encoding="utf-8"))
    return {}


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def check(context: PolicyContext) -> tuple[bool, str]:
    """Kiểm tra chính sách bảo mật cho từng tool call (PEP).

    Trả về (allow, reason) với reason không bao giờ rỗng.
    """
    # 1. Kiểm tra data_classification hợp lệ
    valid_classifications = {"public", "internal", "restricted"}
    if context.data_classification not in valid_classifications:
        return (
            False,
            f"Invalid data_classification: {context.data_classification!r}. Must be one of {valid_classifications}",
        )

    # 2. Rule TỐI THIỂU bắt buộc: restricted + egress_enabled=True -> DENY tuyệt đối
    if context.data_classification == "restricted" and context.egress_enabled:
        return (
            False,
            "Egress denied: egress is strictly prohibited when data classification is restricted",
        )

    # 3. Kiểm tra principal (danh tính người dùng / OBO)
    principals = _load_principals()
    if not context.principal_id or context.principal_id not in principals:
        return False, f"Unknown or missing principal: {context.principal_id!r}"

    principal_info = principals[context.principal_id]

    # 4. Kiểm tra thời hạn cấp quyền (expires_at) theo UTC
    if not context.expires_at:
        return False, "Missing expires_at timestamp for delegation/token"
    try:
        exp_dt = datetime.fromisoformat(context.expires_at)
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        now_dt = datetime.now(timezone.utc)
        if exp_dt <= now_dt:
            return (
                False,
                f"Principal token expired at {context.expires_at} (current UTC: {now_dt.isoformat()})",
            )
    except Exception as exc:
        return False, f"Invalid expires_at format {context.expires_at!r}: {exc}"

    # 5. Kiểm tra mục đích (request_purpose)
    allowed_purposes = principal_info.get("purposes", [])
    if context.request_purpose not in allowed_purposes:
        return (
            False,
            f"Purpose {context.request_purpose!r} not permitted for principal {context.principal_id}",
        )

    # 6. Kiểm tra quyền hạn gọi tool (giao giữa principal.allowed_tools và agent_scopes)
    tool = context.requested_tool
    if not tool:
        return False, "Missing requested_tool"

    allowed_tools = principal_info.get("allowed_tools", [])
    if tool not in allowed_tools:
        return (
            False,
            f"Tool {tool!r} not in allowed_tools for principal {context.principal_id}",
        )

    if not context.agent_scopes or tool not in context.agent_scopes:
        return False, f"Tool {tool!r} exceeds agent_scopes {context.agent_scopes}"

    # Nếu delegation_depth > 0, quyền phải nằm trong cả parent_scopes
    if context.delegation_depth > 0:
        if not context.parent_scopes or tool not in context.parent_scopes:
            return (
                False,
                f"Delegation depth {context.delegation_depth}: tool {tool!r} exceeds parent_scopes {context.parent_scopes}",
            )

    # 7. Cho phép khi mọi điều kiện đều hợp lệ
    return (
        True,
        f"Allowed: {context.principal_id} is authorized for {tool} (purpose: {context.request_purpose})",
    )
