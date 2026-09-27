"""报送快照服务：截止前把“筛选条件 + 数据版本”冻结进 SQLite。

核心不变量：
- 生成快照是【唯一】读取源数据的时刻：命中筛选条件的材料当前版本被
  逐行复制进冻结表，同时把规范化筛选条件与快照指纹一并写入；
- 之后源数据上传新版本、撤回、登记新材料，都只影响源表，已报送摘要
  永远由冻结行确定性汇总得到——下载返回固定摘要；
- 快照必须在报送截止前生成；截止已过的请求被拒绝（409）。
"""
from __future__ import annotations

from ..domain.enums import MaterialKind, Role, Sensitivity
from ..domain.errors import (
    DeadlineExceededError,
    NotFoundError,
    PermissionDeniedError,
    ValidationError,
)
from ..domain.models import ReportSnapshot, SnapshotFrozenRow, User
from ..domain.snapshot import (
    SNAPSHOT_SCOPES,
    build_summary,
    encode_summary,
    normalize_filters,
    snapshot_fingerprint,
)
from .base import Service, require_roles
from .timeutil import now_is_past, resolve_deadline

SNAPSHOT_STATUS_FROZEN = "frozen"


class SnapshotService(Service):
    # ------------------------------------------------------------ 生成快照
    def create_snapshot(
        self,
        actor: User,
        *,
        filters: dict | None = None,
        deadline_local_iso: str | None = None,
        deadline_timezone: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        require_roles(
            actor,
            Role.INSTITUTION_ADMIN,
            Role.QUALITY_AUTHORITY,
        )
        normalized = normalize_filters(filters or {})
        self._validate_filters(normalized)
        # 机构用户只能冻结本机构数据；权威机构/审计可指定或留空（全量）
        if actor.institution_id is not None and not actor.has_role(
            Role.QUALITY_AUTHORITY
        ) and not actor.has_role(Role.AUDITOR):
            normalized["institution_id"] = actor.institution_id

        deadline_at_utc: str | None = None
        if deadline_local_iso is not None or deadline_timezone is not None:
            if not deadline_local_iso or not deadline_timezone:
                raise ValidationError(
                    "截止时间需要同时提供 deadline_local_iso 与 deadline_timezone"
                )
            try:
                resolved = resolve_deadline(deadline_local_iso, deadline_timezone)
            except ValueError as exc:
                raise ValidationError(str(exc)) from exc
            deadline_at_utc = resolved.at_utc_iso
            if now_is_past(deadline_at_utc, self.clock.now_utc()):
                raise DeadlineExceededError(
                    "报送截止已过，不能再生成报送快照",
                    details={"deadline_at_utc": deadline_at_utc},
                )

        def work() -> dict:
            rows = self.repo.select_current_versions_for_snapshot(
                institution_id=normalized["institution_id"],
                kind=normalized["kind"],
                sensitivity=normalized["sensitivity"],
                include_withdrawn=normalized["include_withdrawn"],
            )
            snapshot_id = self.ids.new_id("snap")
            created_at = self.clock.now_iso()
            frozen = [
                SnapshotFrozenRow(
                    snapshot_id=snapshot_id,
                    material_id=r.material_id,
                    institution_id=r.institution_id,
                    kind=r.kind,
                    sensitivity=r.sensitivity,
                    title=r.title,
                    version_id=r.version_id,
                    version_no=r.version_no,
                    sha256=r.sha256,
                    size=r.size,
                    withdrawn=r.frozen(),
                )
                for r in rows
            ]
            fingerprint = snapshot_fingerprint(
                snapshot_id,
                normalized,
                [
                    {
                        "material_id": r.material_id,
                        "institution_id": r.institution_id,
                        "kind": r.kind,
                        "sensitivity": r.sensitivity,
                        "title": r.title,
                        "version_id": r.version_id,
                        "version_no": r.version_no,
                        "sha256": r.sha256,
                        "size": r.size,
                        "withdrawn": r.withdrawn,
                    }
                    for r in frozen
                ],
                created_at,
            )
            snapshot = ReportSnapshot(
                snapshot_id=snapshot_id,
                scope=normalized["scope"],
                institution_id=normalized["institution_id"] or "",
                filters=normalized,
                status=SNAPSHOT_STATUS_FROZEN,
                created_by=actor.user_id,
                created_at=created_at,
                fingerprint=fingerprint,
                row_count=len(frozen),
                deadline_at_utc=deadline_at_utc,
                deadline_timezone=deadline_timezone,
            )
            self.repo.insert_snapshot(snapshot)
            self.repo.insert_snapshot_rows(frozen)
            self.audit(
                actor.user_id, "snapshot.frozen",
                institution_id=snapshot.institution_id or None,
                detail={
                    "snapshot_id": snapshot_id,
                    "filters": normalized,
                    "row_count": len(frozen),
                    "fingerprint": fingerprint,
                },
            )
            return self._snapshot_dict(snapshot)

        return self.idempotent(idempotency_key, work)

    # -------------------------------------------------------------- 查询
    def get_snapshot(self, actor: User, snapshot_id: str) -> dict:
        snapshot = self._load_for_read(actor, snapshot_id)
        return self._snapshot_dict(snapshot)

    def list_snapshots(self, actor: User) -> list[dict]:
        require_roles(
            actor,
            Role.INSTITUTION_ADMIN,
            Role.QUALITY_AUTHORITY,
            Role.AUDITOR,
        )
        if actor.has_role(Role.QUALITY_AUTHORITY) or actor.has_role(Role.AUDITOR):
            snapshots = self.repo.list_snapshots(None)
        else:
            snapshots = self.repo.list_snapshots(actor.institution_id)
        return [self._snapshot_dict(s) for s in snapshots]

    # ---------------------------------------------------------- 固定摘要
    def build_summary(self, actor: User, snapshot_id: str) -> dict:
        """已报送摘要：只依据冻结行汇总，绝不回查源数据表。"""
        snapshot = self._load_for_read(actor, snapshot_id)
        rows = self.repo.get_snapshot_rows(snapshot.snapshot_id)
        return build_summary(
            {
                "snapshot_id": snapshot.snapshot_id,
                "scope": snapshot.scope,
                "filters": snapshot.filters,
                "created_at": snapshot.created_at,
                "created_by": snapshot.created_by,
                "fingerprint": snapshot.fingerprint,
            },
            [
                {
                    "material_id": r.material_id,
                    "institution_id": r.institution_id,
                    "kind": r.kind,
                    "sensitivity": r.sensitivity,
                    "title": r.title,
                    "version_id": r.version_id,
                    "version_no": r.version_no,
                    "sha256": r.sha256,
                    "size": r.size,
                    "withdrawn": r.withdrawn,
                }
                for r in rows
            ],
        )

    def download_summary(
        self, actor: User, snapshot_id: str
    ) -> tuple[dict, bytes]:
        """下载固定摘要字节；两次下载（以及源数据变化后）字节完全一致。"""
        summary = self.build_summary(actor, snapshot_id)
        meta = {
            "snapshot_id": summary["snapshot_id"],
            "fingerprint": summary["fingerprint"],
            "row_count": summary["row_count"],
            "created_at": summary["created_at"],
            "media_type": "application/json",
            "filename": f"report-snapshot-{summary['snapshot_id']}.json",
        }
        return meta, encode_summary(summary)

    # -------------------------------------------------------------- 辅助
    def _load_for_read(self, actor: User, snapshot_id: str) -> ReportSnapshot:
        require_roles(
            actor,
            Role.INSTITUTION_ADMIN,
            Role.QUALITY_AUTHORITY,
            Role.AUDITOR,
        )
        snapshot = self.repo.get_snapshot(snapshot_id)
        if snapshot is None:
            raise NotFoundError("报送快照不存在", details={"snapshot_id": snapshot_id})
        if (
            snapshot.institution_id
            and snapshot.institution_id != actor.institution_id
            and not actor.has_role(Role.QUALITY_AUTHORITY)
            and not actor.has_role(Role.AUDITOR)
        ):
            raise PermissionDeniedError("不能查看其他机构的报送快照")
        return snapshot

    @staticmethod
    def _validate_filters(filters: dict) -> None:
        if filters["scope"] not in SNAPSHOT_SCOPES:
            raise ValidationError(
                "未知快照范围", details={"scope": filters["scope"]}
            )
        if filters["kind"] is not None:
            kinds = {k.value for k in MaterialKind}
            if filters["kind"] not in kinds:
                raise ValidationError(
                    "未知材料类型", details={"kind": filters["kind"]}
                )
        if filters["sensitivity"] is not None:
            sens = {s.value for s in Sensitivity}
            if filters["sensitivity"] not in sens:
                raise ValidationError(
                    "未知敏感度", details={"sensitivity": filters["sensitivity"]}
                )

    @staticmethod
    def _snapshot_dict(s: ReportSnapshot, *, replayed: bool = False) -> dict:
        return {
            "snapshot_id": s.snapshot_id,
            "scope": s.scope,
            "institution_id": s.institution_id or None,
            "filters": dict(s.filters),
            "status": s.status,
            "created_by": s.created_by,
            "created_at": s.created_at,
            "fingerprint": s.fingerprint,
            "row_count": s.row_count,
            "deadline_at_utc": s.deadline_at_utc,
            "deadline_timezone": s.deadline_timezone,
            "replayed": replayed,
        }
