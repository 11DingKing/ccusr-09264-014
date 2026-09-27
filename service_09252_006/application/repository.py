"""仓库抽象端口。

应用服务只依赖此接口；SQLite 实现见 persistence 层。所有涉及多步
状态推进的用例必须在 transaction() 上下文中完成，以保证并发复审下
的可串行化与崩溃可恢复。
"""
from __future__ import annotations

import abc
from contextlib import AbstractContextManager

from ..domain.models import (
    AuditEntry,
    Blob,
    Material,
    MaterialVersion,
    Objection,
    PackageEntry,
    ReportSnapshot,
    ReviewPackage,
    ReviewRequest,
    SnapshotEntry,
    User,
)


class Repository(abc.ABC):
    # ---- 事务/生命周期 ----
    @abc.abstractmethod
    def transaction(self) -> AbstractContextManager[None]:
        """串行写事务（SQLite 实现为 BEGIN IMMEDIATE）。"""

    @abc.abstractmethod
    def close(self) -> None: ...

    # ---- 用户/角色 ----
    @abc.abstractmethod
    def upsert_user(self, user: User) -> None: ...

    @abc.abstractmethod
    def get_user(self, user_id: str) -> User | None: ...

    @abc.abstractmethod
    def put_token(self, token: str, user_id: str, at: str) -> None: ...

    @abc.abstractmethod
    def get_user_by_token(self, token: str) -> User | None: ...

    # ---- 幂等键 ----
    @abc.abstractmethod
    def get_idempotent_result(self, key: str) -> dict | None: ...

    @abc.abstractmethod
    def save_idempotent_result(self, key: str, result: dict) -> None: ...

    # ---- 材料与版本 ----
    @abc.abstractmethod
    def put_blob(self, blob: Blob) -> None: ...

    @abc.abstractmethod
    def get_blob(self, sha256: str) -> Blob | None: ...

    @abc.abstractmethod
    def insert_material(self, material: Material) -> None: ...

    @abc.abstractmethod
    def get_material(self, material_id: str) -> Material | None: ...

    @abc.abstractmethod
    def insert_version(self, version: MaterialVersion) -> None: ...

    @abc.abstractmethod
    def get_version(self, version_id: str) -> MaterialVersion | None: ...

    @abc.abstractmethod
    def find_version_by_digest(
        self, material_id: str, sha256: str
    ) -> MaterialVersion | None: ...

    @abc.abstractmethod
    def list_versions(self, material_id: str) -> list[MaterialVersion]: ...

    @abc.abstractmethod
    def mark_version_withdrawn(
        self, version_id: str, withdrawn: bool, at: str
    ) -> bool: ...

    @abc.abstractmethod
    def mark_material_withdrawn(
        self, material_id: str, withdrawn: bool
    ) -> bool: ...

    # ---- 评审包 ----
    @abc.abstractmethod
    def insert_package(self, package: ReviewPackage) -> None: ...

    @abc.abstractmethod
    def get_package(self, package_id: str) -> ReviewPackage | None: ...

    @abc.abstractmethod
    def list_packages(
        self, institution_id: str | None = None,
    ) -> list[ReviewPackage]: ...

    @abc.abstractmethod
    def insert_entry(self, entry: PackageEntry) -> None: ...

    @abc.abstractmethod
    def entry_exists(self, package_id: str, version_id: str) -> bool: ...

    @abc.abstractmethod
    def transition_package_status(
        self,
        package_id: str,
        expected_status: str,
        new_status: str,
        **fields,
    ) -> bool:
        """条件更新；状态不再是 expected_status 时返回 False（并发冲突）。"""

    # ---- 评审请求 ----
    @abc.abstractmethod
    def insert_request(self, request: ReviewRequest) -> None: ...

    @abc.abstractmethod
    def get_request(self, request_id: str) -> ReviewRequest | None: ...

    @abc.abstractmethod
    def list_requests_by_package(self, package_id: str) -> list[ReviewRequest]: ...

    @abc.abstractmethod
    def list_active_requests_by_reviewer(self, reviewer_id: str) -> list[ReviewRequest]:
        """状态属于 pending/accepted/completed 的请求（权限变化依据）。"""

    @abc.abstractmethod
    def update_request(self, request: ReviewRequest) -> None: ...

    # ---- 异议 ----
    @abc.abstractmethod
    def insert_objection(self, objection: Objection) -> None: ...

    @abc.abstractmethod
    def list_objections_by_package(self, package_id: str) -> list[Objection]: ...

    # ---- 报送快照 ----
    @abc.abstractmethod
    def insert_snapshot(self, snapshot: ReportSnapshot) -> None:
        """连同条目与内容字节副本一并写入（须在调用方事务内）。"""

    @abc.abstractmethod
    def get_snapshot(self, snapshot_id: str) -> ReportSnapshot | None: ...

    @abc.abstractmethod
    def list_snapshots(
        self, institution_id: str | None = None,
    ) -> list[ReportSnapshot]: ...

    @abc.abstractmethod
    def find_live_materials_for_snapshot(
        self,
        institution_id: str,
        *,
        kinds: tuple[str, ...] | None = None,
        sensitivity: str | None = None,
    ) -> list[tuple[Material, MaterialVersion]]:
        """按冻结前的筛选条件选取每份【未撤回】材料的当前版本。

        仅返回材料未撤回、当前版本存在且未撤回的 (material, version)。
        """

    @abc.abstractmethod
    def put_snapshot_blob_copy(
        self, snapshot_id: str, sha256: str, data: bytes, media_type: str
    ) -> None: ...

    @abc.abstractmethod
    def get_snapshot_blob_copy(
        self, snapshot_id: str, sha256: str
    ) -> tuple[bytes, str] | None:
        """返回快照自有的内容副本 (data, media_type)，不读源 blobs 表。"""

    # ---- 审计 ----
    @abc.abstractmethod
    def insert_audit(self, entry: AuditEntry) -> None: ...

    @abc.abstractmethod
    def list_audit(
        self, package_id: str | None = None, limit: int = 200
    ) -> list[AuditEntry]: ...
