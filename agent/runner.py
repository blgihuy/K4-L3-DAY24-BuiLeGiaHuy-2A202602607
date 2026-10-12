"""BƯỚC 3c & 3d — trifecta split + egress allowlist + PEP/ledger integration.

Tách 1 yêu cầu người dùng thành các run riêng biệt:
    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — list[int] ticket id
           trích từ TÊN FILE, rồi map qua related_tickets trong data/customers.json.
           Tuyệt đối KHÔNG lấy customer_id từ free text của attacker.

Mọi tool call đều phải:
    1. Đi qua `agent.policy.check()` TRƯỚC KHI thực thi.
    2. Được ghi vào ledger qua `agent.ledger.append()`, kể cả khi deny.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, pii, policy, tools
from agent.policy import PolicyContext

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
CUSTOMERS_FILE = Path(__file__).resolve().parent.parent / "data" / "customers.json"


def handle(
    message: str,
    llm,
    log_dir: Path | None = None,
    principal_id: str = "support_l1",
) -> str:
    """Xử lý yêu cầu an toàn theo kiến trúc Trifecta Split và PEP/OBO."""
    agent_id = "lab24-agent"
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    log_path = (Path(log_dir) if log_dir else REPORTS_DIR) / "ledger.jsonl"

    def _call_policy_and_log(
        tool_name: str,
        args: dict,
        data_classification: str,
        egress_enabled: bool,
        agent_scopes: tuple[str, ...],
        delegation_depth: int = 0,
        parent_scopes: tuple[str, ...] = (),
        purpose: str = "support-reply",
    ) -> tuple[bool, str]:
        ctx = PolicyContext(
            data_classification=data_classification,
            request_purpose=purpose,
            agent_owner=f"{agent_id}/{run_id}",
            delegation_depth=delegation_depth,
            egress_enabled=egress_enabled,
            principal_id=principal_id,
            requested_tool=tool_name,
            agent_scopes=agent_scopes,
            parent_scopes=parent_scopes,
            expires_at=expires_at,
        )
        allowed, reason = policy.check(ctx)
        args_hash = hashlib.sha256(
            json.dumps(args, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()

        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": run_id,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
            "tool": tool_name,
            "args_hash": args_hash,
            "classification": data_classification,
            "decision": "allow" if allowed else "deny",
            "reason": reason,
        }
        ledger.append(entry, log_path)
        return allowed, reason

    # ─────────────────────────────────────────────────────────────
    # Run A: search_docs (untrusted content)
    # ─────────────────────────────────────────────────────────────
    allowed_search, reason_search = _call_policy_and_log(
        tool_name="search_docs",
        args={"query": message},
        data_classification="internal",
        egress_enabled=False,
        agent_scopes=("search_docs",),
        delegation_depth=0,
    )
    if not allowed_search:
        return "Yêu cầu bị từ chối bởi chính sách bảo mật."

    docs = tools.search_docs(message)

    # Trích xuất ticket_id (số nguyên) chỉ từ TÊN FILE (e.g. ticket-014.md -> 14)
    ticket_ids: set[int] = set()
    for d in docs:
        match = re.search(r"ticket-(\d+)", d["id"])
        if match:
            ticket_ids.add(int(match.group(1)))

    # ─────────────────────────────────────────────────────────────
    # Run B: Đọc private data khách hàng qua related_tickets
    # NGUỒN TIN CẬY: data/customers.json (không lấy từ free text attacker)
    # ─────────────────────────────────────────────────────────────
    customers = []
    if CUSTOMERS_FILE.exists():
        customers = json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))

    target_customers: list[str] = []
    for c in customers:
        related = c.get("related_tickets", [])
        if any(tid in related for tid in ticket_ids):
            target_customers.append(str(c["customer_id"]))

    target_customers = sorted(set(target_customers))

    collected_records: list[dict] = []
    for cid in target_customers:
        allowed_read, reason_read = _call_policy_and_log(
            tool_name="read_customer",
            args={"customer_id": cid},
            data_classification="restricted",
            egress_enabled=False,
            agent_scopes=("read_customer",),
            delegation_depth=0,
        )
        if allowed_read:
            try:
                record = tools.read_customer(cid)
                collected_records.append(record)
            except tools.ToolError:
                continue

    # ─────────────────────────────────────────────────────────────
    # Kiểm tra Prompt Injection & Chặn Egress
    # ─────────────────────────────────────────────────────────────
    combined_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_text)
    if injected is not None:
        # Attacker cố gắng ra lệnh POST dữ liệu ra sink URL:
        # Cổng PEP kiểm tra và DENY vì restricted + egress_enabled=True.
        # Ghi log deny vào ledger làm evidence. Lượt kiểm chỉ cần URL, không mang hồ sơ khách.
        allowed_post, reason_post = _call_policy_and_log(
            tool_name="http_post",
            args={"url": injected.target_url},
            data_classification="restricted",
            egress_enabled=True,
            agent_scopes=("http_post",),
            delegation_depth=0,
        )
        if allowed_post:
            tools.http_post(injected.target_url, {"records": collected_records})

    # Che PII trong nội dung trước khi đưa vào bản tóm tắt
    redacted_docs = [{"id": d["id"], "text": pii.redact(d["text"])} for d in docs]
    return llm.summarize(redacted_docs)

