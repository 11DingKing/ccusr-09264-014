"""报送快照服务：截止前生成不可变的报送快照。

核心不变量：
- 生成快照时，按【当时的筛选条件】选取每份未撤回材料的当前有效版本，
  把筛选条件、版本集合（material/version/sha256/kind/sensitivity/version_no）
  与生成时刻一起做规范化哈希，得到 snapshot_fingerprint；
- 快照同时把【固定摘要】（JSON）与【内容字节副本】落库。此后源数据
  （上传新版本、撤回版本、删除/改写 blobs 字节、新增材料）如何变化，
  已生成快照的摘要与下载内容都不变——“报送当时报上去的是什么”可证；
- 快照不支持修改/删除；需要反映新数据只能再生成一份新快照。
"""
from __future__ import annotations

import json

from ..domain.enums import MaterialKind, Role, Sensitivity
from ..domain.errors import (
    NotFoundError,
    PermissionDeniedError,
    ValidationError,
)
from ..domain.fingerprint import snapshot_fingerprint, summary_fingerprint
from ..domain.models import ReportSnapshot, SnapshotEntry, User
from .base import Service, require_roles


class SnapshotService(Service):
    # ------------------------------------------------------------- 生成快照
    def create_snapshot(
        self,
        actor: User,
        *,
        title: str,
        kinds: list[str] | tuple[str, ...] | None = None,
        sensitivity: str | None = None,
        snapshot_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        require_roles(actor, Role.INSTITUTION_ADMIN, Role.QUALITY_AUTHORITY)
        if not title.strip():
            raise ValidationError("报送快照标题不能为空")
        institution_id = actor.institution_id or ""
        if not institution_id:
            raise PermissionDeniedError("权威机构不能直接生成机构报送快照")
        kind_tuple = self._validate_filters(kinds, sensitivity)

        def work() -> dict:
            sid = snapshot_id or self.ids.new_id("snap")
            existing = self.repo.get_snapshot(sid)
            if existing is not None:
                return self._snapshot_dict(existing)

            created_at = self.clock.now_iso()
            filters = self._freeze_filters(kind_tuple, sensitivity)
            pairs = self.repo.find_live_materials_for_snapshot(
                institution_id,
                kinds=kind_tuple,
                sensitivity=sensitivity,
            )
            pairs.sort(key=lambda mv: (mv[0].material_id, mv[1].version_id))

            entries: list[SnapshotEntry] = []
            items: list[dict] = []
            blob_copies: list[tuple[str, bytes, str]] = []
            total_size = 0
            for ordinal, (material, version) in enumerate(pairs):
                blob = self.repo.get_blob(version.sha256)
                if blob is None:
                    raise NotFoundError(
                        "材料内容字节缺失，无法生成报送快照",
                        details={"version_id": version.version_id},
                    )
                entry = SnapshotEntry(
                    snapshot_id=sid,
                    material_id=material.material_id,
                    version_id=version.version_id,
                    sha256=version.sha256,
                    kind=material.kind,
                    sensitivity=material.sensitivity,
                    title=material.title,
                    media_type=version.media_type,
                    version_no=version.version_no,
                    size=version.size,
                    ordinal=ordinal,
                )
                entries.append(entry)
                # 内容字节副本随快照冻结：源 blobs 事后删改不影响报送
                blob_copies.append((version.sha256, blob.data, version.media_type))
                items.append(
                    {
                        "material_id": material.material_id,
                        "version_id": version.version_id,
                        "sha256": "sha256:" + version.sha256,
                        "kind": material.kind,
                        "sensitivity": material.sensitivity,
                        "title": material.title,
                        "version_no": version.version_no,
                        "size": version.size,
                    }
                )
                total_size += version.size

            fp = snapshot_fingerprint(
                sid,
                institution_id,
                filters,
                [
                    {
                        "material_id": e.material_id,
                        "version_id": e.version_id,
                        "sha256": e.sha256,
                        "kind": e.kind,
                        "sensitivity": e.sensitivity,
                        "version_no": e.version_no,
                    }
                    for e in entries
                ],
                created_at,
            )
            summary = {
                "snapshot_id": sid,
                "title": title.strip(),
                "institution_id": institution_id,
                "generated_at": created_at,
                "filters": filters,
                "entry_count": len(entries),
                "total_size": total_size,
                "fingerprint": fp,
                "items": items,
            }
            # 摘要内容指纹独立于摘要本身（不自引用），离线可重算复核
            sum_fp = summary_fingerprint(summary)

            snapshot = ReportSnapshot(
                snapshot_id=sid,
                institution_id=institution_id,
                title=title.strip(),
                filters=filters,
                summary=summary,
                fingerprint=fp,
                summary_fingerprint=sum_fp,
                entry_count=len(entries),
                total_size=total_size,
                created_by=actor.user_id,
                created_at=created_at,
                entries=entries,
            )
            self.repo.insert_snapshot(snapshot)
            # 主记录存在后再写内容副本（满足外键）；仍在同一写事务内
            for sha256, data_bytes, media_type in blob_copies:
                self.repo.put_snapshot_blob_copy(sid, sha256, data_bytes, media_type)
            self.audit(
                actor.user_id, "snapshot.created",
                institution_id=institution_id,
                detail={"snapshot_id": sid, "fingerprint": fp,
                        "entry_count": len(entries)},
            )
            return self._snapshot_dict(snapshot)

        return self.idempotent(idempotency_key, work)

    # ------------------------------------------------------------- 视图/下载
    def get_snapshot(self, actor: User, snapshot_id: str) -> dict:
        snapshot = self._load_authorized(actor, snapshot_id)
        return self._snapshot_dict(snapshot)

    def list_snapshots(self, actor: User) -> list[dict]:
        require_roles(
            actor,
            Role.INSTITUTION_ADMIN,
            Role.QUALITY_AUTHORITY,
            Role.AUDITOR,
        )
        if actor.has_role(Role.AUDITOR) or actor.has_role(Role.QUALITY_AUTHORITY):
            snapshots = self.repo.list_snapshots(None)
        else:
            snapshots = self.repo.list_snapshots(actor.institution_id or "")
        return [self._snapshot_dict(s) for s in snapshots]

    def download_summary(
        self, actor: User, *, snapshot_id: str
    ) -> tuple[dict, bytes]:
        """返回报送快照【冻结的固定摘要】JSON 字节。

        直接读快照生成时落库的 summary，源数据随后变化不影响其内容。
        """
        snapshot = self._load_authorized(actor, snapshot_id)
        body = self._summary_bytes(snapshot)
        return self._snapshot_dict(snapshot), body

    def download_entry(
        self, actor: User, *, snapshot_id: str, version_id: str
    ) -> tuple[dict, bytes, str]:
        """通过快照条目下载内容字节；字节取自快照自有副本。"""
        snapshot = self._load_authorized(actor, snapshot_id)
        entry = next(
            (e for e in snapshot.entries if e.version_id == version_id), None
        )
        if entry is None:
            raise NotFoundError("该材料版本不在此报送快照中")
        copy = self.repo.get_snapshot_blob_copy(snapshot_id, entry.sha256)
        if copy is None:
            raise NotFoundError("快照内容副本缺失，无法提供")
        data, media_type = copy
        meta = {
            "snapshot_id": snapshot_id,
            "version_id": entry.version_id,
            "material_id": entry.material_id,
            "sha256": "sha256:" + entry.sha256,
            "media_type": media_type,
            "size": entry.size,
        }
        return meta, data, media_type

    # ------------------------------------------------------------- 辅助
    def _load_authorized(self, actor: User, snapshot_id: str) -> ReportSnapshot:
        # 报送摘要含敏感反馈的内容指纹，仅机构管理员/权威/审计可见，
        # 与最小披露策略保持一致（提交人、评审人不参与报送）。
        require_roles(
            actor,
            Role.INSTITUTION_ADMIN,
            Role.QUALITY_AUTHORITY,
            Role.AUDITOR,
        )
        snapshot = self.repo.get_snapshot(snapshot_id)
        if snapshot is None:
            raise NotFoundError("报送快照不存在")
        if (
            actor.institution_id != snapshot.institution_id
            and not actor.has_role(Role.QUALITY_AUTHORITY)
            and not actor.has_role(Role.AUDITOR)
        ):
            raise PermissionDeniedError("不能查看其他机构报送快照")
        return snapshot

    @staticmethod
    def _summary_bytes(snapshot: ReportSnapshot) -> bytes:
        return json.dumps(
            snapshot.summary, ensure_ascii=False, sort_keys=True, indent=2
        ).encode("utf-8")

    @staticmethod
    def _validate_filters(
        kinds: list[str] | tuple[str, ...] | None,
        sensitivity: str | None,
    ) -> tuple[str, ...] | None:
        valid_kinds = {k.value for k in MaterialKind}
        if kinds is not None:
            kind_list = [k for k in kinds if k]
            bad = [k for k in kind_list if k not in valid_kinds]
            if bad:
                raise ValidationError("未知材料类型", details={"kinds": bad})
        else:
            kind_list = None
        if sensitivity is not None and sensitivity not in {
            s.value for s in Sensitivity
        }:
            raise ValidationError(
                "未知敏感度", details={"sensitivity": sensitivity}
            )
        if kind_list is None:
            return None
        # 去重并排序：筛选条件的规范表示不依赖调用方传入顺序
        return tuple(sorted(set(kind_list)))

    @staticmethod
    def _freeze_filters(
        kinds: tuple[str, ...] | None, sensitivity: str | None
    ) -> dict:
        return {
            "kinds": list(kinds) if kinds is not None else None,
            "sensitivity": sensitivity,
        }

    @staticmethod
    def _snapshot_dict(s: ReportSnapshot) -> dict:
        return {
            "snapshot_id": s.snapshot_id,
            "institution_id": s.institution_id,
            "title": s.title,
            "filters": s.filters,
            "entry_count": s.entry_count,
            "total_size": s.total_size,
            "fingerprint": s.fingerprint,
            "summary_fingerprint": s.summary_fingerprint,
            "created_by": s.created_by,
            "created_at": s.created_at,
        }
