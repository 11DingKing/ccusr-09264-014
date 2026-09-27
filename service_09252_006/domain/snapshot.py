"""报送快照：筛选条件与数据版本冻结（纯函数）。

报送截止前生成快照时，把命中筛选条件的材料【当前版本】逐行复制到
独立冻结表；之后源数据（新版本、撤回、新登记材料）如何变化，都不再
影响已报送摘要——下载摘要只对冻结行做确定性汇总，并对“筛选条件 +
冻结行 + 生成时刻”计算快照指纹，使报送内容可证明、可离线核验。
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .fingerprint import ALGORITHM, digest_json

SNAPSHOT_SCHEMA = "quality-reporting-snapshot/v1"
SCOPE_CURRENT_MATERIALS = "current_materials"
SNAPSHOT_SCOPES = frozenset({SCOPE_CURRENT_MATERIALS})

FILTER_KEYS = (
    "scope",
    "institution_id",
    "kind",
    "sensitivity",
    "include_withdrawn",
)


@dataclass(frozen=True)
class CurrentVersionRow:
    """快照生成时刻，材料当前版本在源表中的一行取值。"""

    material_id: str
    institution_id: str
    kind: str
    sensitivity: str
    title: str
    material_withdrawn: bool
    version_id: str
    version_no: int
    sha256: str
    size: int
    version_withdrawn: bool

    def frozen(self) -> bool:
        return self.material_withdrawn or self.version_withdrawn


def normalize_filters(filters: Mapping[str, Any]) -> dict:
    """把外部输入规整成确定性的筛选条件（缺失即 None/false）。"""
    return {
        "scope": str(filters.get("scope") or SCOPE_CURRENT_MATERIALS),
        "institution_id": (
            None
            if filters.get("institution_id") in (None, "")
            else str(filters["institution_id"])
        ),
        "kind": None if filters.get("kind") in (None, "") else str(filters["kind"]),
        "sensitivity": (
            None
            if filters.get("sensitivity") in (None, "")
            else str(filters["sensitivity"])
        ),
        "include_withdrawn": bool(filters.get("include_withdrawn", False)),
    }


def frozen_row_dict(row: Mapping[str, Any]) -> dict:
    """冻结行进指纹/摘要时的规范化字段集合。"""
    return {
        "material_id": str(row["material_id"]),
        "institution_id": str(row["institution_id"]),
        "kind": str(row["kind"]),
        "sensitivity": str(row["sensitivity"]),
        "title": str(row["title"]),
        "version_id": str(row["version_id"]),
        "version_no": int(row["version_no"]),
        "sha256": str(row["sha256"]),
        "size": int(row["size"]),
        "withdrawn": bool(row["withdrawn"]),
    }


def snapshot_fingerprint(
    snapshot_id: str,
    filters: Mapping[str, Any],
    rows: Iterable[Mapping[str, Any]],
    created_at: str,
) -> str:
    """对“筛选条件 + 冻结行集合 + 生成时刻”做规范化哈希。"""
    normalized_rows = sorted(
        (frozen_row_dict(r) for r in rows),
        key=lambda r: r["material_id"],
    )
    payload = {
        "schema": SNAPSHOT_SCHEMA,
        "snapshot_id": snapshot_id,
        "filters": {k: filters.get(k) for k in FILTER_KEYS},
        "created_at": created_at,
        "rows": normalized_rows,
    }
    return ALGORITHM + ":" + digest_json(payload)


def build_summary(
    snapshot: Mapping[str, Any],
    rows: Iterable[Mapping[str, Any]],
) -> dict:
    """只依据冻结行生成确定性摘要；绝不回查源数据表。"""
    normalized_rows = sorted(
        (frozen_row_dict(r) for r in rows),
        key=lambda r: r["material_id"],
    )
    by_kind: dict[str, dict[str, int]] = {}
    total_bytes = 0
    sensitive_count = 0
    withdrawn_count = 0
    for row in normalized_rows:
        bucket = by_kind.setdefault(row["kind"], {"count": 0, "bytes": 0})
        bucket["count"] += 1
        bucket["bytes"] += row["size"]
        total_bytes += row["size"]
        if row["sensitivity"] == "sensitive":
            sensitive_count += 1
        if row["withdrawn"]:
            withdrawn_count += 1
    return {
        "schema": SNAPSHOT_SCHEMA,
        "snapshot_id": snapshot["snapshot_id"],
        "scope": snapshot["scope"],
        "filters": snapshot["filters"],
        "created_at": snapshot["created_at"],
        "created_by": snapshot["created_by"],
        "fingerprint": snapshot["fingerprint"],
        "row_count": len(normalized_rows),
        "total_bytes": total_bytes,
        "sensitive_count": sensitive_count,
        "withdrawn_count": withdrawn_count,
        "by_kind": {kind: by_kind[kind] for kind in sorted(by_kind)},
        "rows": normalized_rows,
    }


def encode_summary(summary: Mapping[str, Any]) -> bytes:
    """摘要的确定性线上编码（键排序、缩进固定），两次下载字节一致。"""
    return (
        json.dumps(
            summary,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
