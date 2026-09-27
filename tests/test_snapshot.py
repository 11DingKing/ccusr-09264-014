"""报送快照：筛选条件与数据版本冻结。

覆盖：
- 快照按筛选条件冻结命中材料的【当时当前版本】；
- 快照生成后，源数据上传新版本、撤回版本、登记新材料，已报送摘要
  （含下载字节、指纹、行数、字节数）保持不变；
- 机构范围与角色权限、幂等重放、截止前才可生成；
- 离线核验重算快照指纹，篡改冻结行/筛选条件被检出。
"""
from __future__ import annotations

import unittest

from service_09252_006.application.verification import verify_database
from service_09252_006.domain.enums import MaterialKind, Role, Sensitivity
from service_09252_006.domain.errors import (
    DeadlineExceededError,
    PermissionDeniedError,
    ValidationError,
)
from service_09252_006.domain.snapshot import encode_summary
from tests.flow import upload_material
from tests.support import Harness


class SnapshotFreezeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.admin = self.h.user("admin-a", Role.INSTITUTION_ADMIN)
        self.authority = self.h.user(
            "auth", Role.QUALITY_AUTHORITY, institution_id=None
        )

    def tearDown(self) -> None:
        self.h.close()

    # -------------------------------------------------- 冻结后源数据不影响
    def test_source_changes_after_freeze_do_not_alter_summary(self) -> None:
        syllabus = upload_material(
            self.h, self.admin,
            kind=MaterialKind.SYLLABUS.value,
            data="大纲 v1".encode("utf-8"),
            title="课程大纲",
        )
        feedback = upload_material(
            self.h, self.admin,
            kind=MaterialKind.ENTERPRISE_FEEDBACK.value,
            data="敏感反馈 v1".encode("utf-8"),
            title="企业反馈",
            sensitivity=Sensitivity.SENSITIVE.value,
        )

        created = self.h.ctx.snapshots.create_snapshot(self.admin, filters={})
        sid = created["snapshot_id"]
        self.assertEqual(created["status"], "frozen")
        self.assertEqual(created["row_count"], 2)
        # 机构用户的快照范围被强制收敛到本机构
        self.assertEqual(created["institution_id"], "inst-a")
        self.assertEqual(created["filters"]["institution_id"], "inst-a")

        before = self.h.ctx.snapshots.build_summary(self.admin, sid)
        _, bytes_before = self.h.ctx.snapshots.download_summary(self.admin, sid)
        self.assertEqual(before["fingerprint"], created["fingerprint"])

        # ---- 快照之后源数据发生三类变化 ----
        # 1) 已冻结材料出现新版本
        self.h.ctx.evidence.upload_version(
            self.admin,
            material_id=syllabus.material["material_id"],
            data="大纲 v2，内容完全不同".encode("utf-8"),
        )
        # 2) 冻结的版本被事后撤回
        self.h.ctx.evidence.withdraw_version(
            self.admin, version_id=feedback.version["version_id"]
        )
        # 3) 登记并上传全新材料
        extra = upload_material(
            self.h, self.admin,
            kind=MaterialKind.FACULTY.value,
            data="新增师资材料".encode("utf-8"),
            title="师资",
        )

        after = self.h.ctx.snapshots.build_summary(self.admin, sid)
        _, bytes_after = self.h.ctx.snapshots.download_summary(self.admin, sid)

        # 摘要逐字段与字节都不变
        self.assertEqual(after, before)
        self.assertEqual(bytes_after, bytes_before)
        self.assertEqual(after["fingerprint"], created["fingerprint"])
        self.assertEqual(after["row_count"], 2)
        self.assertEqual(
            {r["version_id"] for r in after["rows"]},
            {syllabus.version["version_id"], feedback.version["version_id"]},
        )
        # 冻结行记录的仍是 v1 字节与大小，撤回标记也未被事后改变
        snap_syllabus = next(
            r for r in after["rows"]
            if r["material_id"] == syllabus.material["material_id"]
        )
        self.assertEqual(snap_syllabus["sha256"], syllabus.version["sha256"].split(":", 1)[1])
        self.assertEqual(snap_syllabus["size"], len("大纲 v1".encode("utf-8")))
        self.assertFalse(snap_syllabus["withdrawn"])

        # 摘要字节即其确定性编码（下载返回固定摘要）
        self.assertEqual(bytes_after, encode_summary(after))

    def test_filters_are_frozen_and_applied_at_creation(self) -> None:
        upload_material(
            self.h, self.admin, kind=MaterialKind.SYLLABUS.value, data=b"a"
        )
        upload_material(
            self.h, self.admin,
            kind=MaterialKind.ENTERPRISE_FEEDBACK.value,
            data=b"secret",
            sensitivity=Sensitivity.SENSITIVE.value,
        )
        created = self.h.ctx.snapshots.create_snapshot(
            self.admin, filters={"kind": MaterialKind.SYLLABUS.value}
        )
        summary = self.h.ctx.snapshots.build_summary(
            self.admin, created["snapshot_id"]
        )
        self.assertEqual(summary["row_count"], 1)
        self.assertEqual(set(summary["by_kind"]), {MaterialKind.SYLLABUS.value})
        # 筛选条件原样冻结在摘要里
        self.assertEqual(summary["filters"]["kind"], MaterialKind.SYLLABUS.value)

    def test_include_withdrawn_captures_withdrawn_at_creation_only(self) -> None:
        item = upload_material(self.h, self.admin, data=b"soon withdrawn")
        # 默认不含撤回材料
        clean = self.h.ctx.snapshots.create_snapshot(self.admin, filters={})
        self.assertEqual(clean["row_count"], 1)

        self.h.ctx.evidence.withdraw_version(
            self.admin, version_id=item.version["version_id"]
        )
        # 事后撤回不改变此前快照
        self.assertEqual(
            self.h.ctx.snapshots.build_summary(self.admin, clean["snapshot_id"])["row_count"],
            1,
        )
        # 新快照默认排除已撤回
        after_default = self.h.ctx.snapshots.create_snapshot(self.admin, filters={})
        self.assertEqual(after_default["row_count"], 0)
        # 显式纳入时，冻结行带 withdrawn=True
        with_withdrawn = self.h.ctx.snapshots.create_snapshot(
            self.admin, filters={"include_withdrawn": True}
        )
        summary = self.h.ctx.snapshots.build_summary(
            self.admin, with_withdrawn["snapshot_id"]
        )
        self.assertEqual(summary["row_count"], 1)
        self.assertEqual(summary["withdrawn_count"], 1)
        self.assertTrue(summary["rows"][0]["withdrawn"])

    # ----------------------------------------------------------- 权限/范围
    def test_other_institution_cannot_read_snapshot(self) -> None:
        upload_material(self.h, self.admin, data=b"inst-a data")
        created = self.h.ctx.snapshots.create_snapshot(self.admin, filters={})
        admin_b = self.h.user("admin-b", Role.INSTITUTION_ADMIN, institution_id="inst-b")
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.snapshots.get_snapshot(admin_b, created["snapshot_id"])
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.snapshots.download_summary(admin_b, created["snapshot_id"])
        # 列表只见本机构
        self.assertEqual(
            self.h.ctx.snapshots.list_snapshots(admin_b), []
        )

    def test_authority_can_freeze_and_read_all_institutions(self) -> None:
        upload_material(self.h, self.admin, data=b"a")
        admin_b = self.h.user("admin-b", Role.INSTITUTION_ADMIN, institution_id="inst-b")
        upload_material(self.h, admin_b, data=b"b")
        created = self.h.ctx.snapshots.create_snapshot(self.authority, filters={})
        self.assertIsNone(created["institution_id"])  # 跨机构全量快照
        summary = self.h.ctx.snapshots.build_summary(
            self.authority, created["snapshot_id"]
        )
        self.assertEqual(summary["row_count"], 2)
        self.assertEqual(
            {r["institution_id"] for r in summary["rows"]},
            {"inst-a", "inst-b"},
        )
        # 权威机构可读机构快照
        one = self.h.ctx.snapshots.create_snapshot(self.admin, filters={})
        self.assertTrue(
            self.h.ctx.snapshots.get_snapshot(
                self.authority, one["snapshot_id"]
            )
        )

    def test_submitter_cannot_create_snapshot(self) -> None:
        submitter = self.h.user("sub-a", Role.INSTITUTION_SUBMITTER)
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.snapshots.create_snapshot(submitter, filters={})

    def test_auditor_is_read_only(self) -> None:
        upload_material(self.h, self.admin, data=b"a")
        auditor = self.h.user("aud", Role.AUDITOR, institution_id=None)
        # 审计不能生成快照（只读）
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.snapshots.create_snapshot(auditor, filters={})
        # 但可跨机构读取与下载已有快照
        created = self.h.ctx.snapshots.create_snapshot(self.admin, filters={})
        view = self.h.ctx.snapshots.get_snapshot(auditor, created["snapshot_id"])
        self.assertEqual(view["snapshot_id"], created["snapshot_id"])
        summary = self.h.ctx.snapshots.build_summary(
            auditor, created["snapshot_id"]
        )
        self.assertEqual(summary["row_count"], 1)
        self.assertEqual(len(self.h.ctx.snapshots.list_snapshots(auditor)), 1)

    def test_invalid_filters_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            self.h.ctx.snapshots.create_snapshot(self.admin, filters={"kind": "nope"})
        with self.assertRaises(ValidationError):
            self.h.ctx.snapshots.create_snapshot(
                self.admin, filters={"sensitivity": "ultra"}
            )

    # ------------------------------------------------------------- 截止约束
    def test_snapshot_rejected_after_deadline(self) -> None:
        upload_material(self.h, self.admin, data=b"a")
        with self.assertRaises(DeadlineExceededError):
            self.h.ctx.snapshots.create_snapshot(
                self.admin,
                filters={},
                deadline_local_iso="2026-09-25T08:30",  # 00:30 UTC，早于时钟 01:00
                deadline_timezone="Asia/Shanghai",
            )

    def test_snapshot_allowed_before_deadline(self) -> None:
        upload_material(self.h, self.admin, data=b"a")
        created = self.h.ctx.snapshots.create_snapshot(
            self.admin,
            filters={},
            deadline_local_iso="2026-09-25T18:00",
            deadline_timezone="Asia/Shanghai",
        )
        self.assertEqual(created["row_count"], 1)
        self.assertEqual(created["deadline_timezone"], "Asia/Shanghai")

    # ------------------------------------------------------------- 幂等
    def test_idempotent_create_replays_same_snapshot(self) -> None:
        upload_material(self.h, self.admin, data=b"a")
        first = self.h.ctx.snapshots.create_snapshot(
            self.admin, filters={}, idempotency_key="snap-key-1"
        )
        second = self.h.ctx.snapshots.create_snapshot(
            self.admin, filters={}, idempotency_key="snap-key-1"
        )
        self.assertEqual(second["snapshot_id"], first["snapshot_id"])
        self.assertTrue(second["replayed"])
        self.assertEqual(second["fingerprint"], first["fingerprint"])
        self.assertEqual(len(self.h.ctx.snapshots.list_snapshots(self.admin)), 1)

    # --------------------------------------------------------- 离线核验
    def test_offline_verification_covers_snapshot(self) -> None:
        upload_material(self.h, self.admin, data=b"a")
        created = self.h.ctx.snapshots.create_snapshot(self.admin, filters={})
        self.h.ctx.close()

        report = verify_database(self.h.db_path)
        self.assertTrue(report.ok)
        self.assertEqual(report.snapshot_count, 1)

        # 篡改冻结行：核验必须失败
        import sqlite3

        conn = sqlite3.connect(self.h.db_path)
        conn.execute(
            "UPDATE snapshot_frozen_rows SET size = size + 100"
            " WHERE snapshot_id = ?",
            (created["snapshot_id"],),
        )
        conn.commit()
        conn.close()
        tampered = verify_database(self.h.db_path)
        self.assertFalse(tampered.ok)
        self.assertTrue(
            any(f["kind"] == "snapshot_fingerprint_mismatch" for f in tampered.failures)
        )


if __name__ == "__main__":
    unittest.main()
