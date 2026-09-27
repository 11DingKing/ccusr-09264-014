"""报送快照：筛选条件/数据版本冻结、固定摘要下载、源数据变化不影响快照、
幂等重放、权限、离线核验，以及 HTTP 端到端。
"""
from __future__ import annotations

import base64
import json
import unittest

from service_09252_006.application.verification import verify_database
from service_09252_006.domain.enums import MaterialKind, Role, Sensitivity
from service_09252_006.domain.errors import PermissionDeniedError, ValidationError
from tests.flow import upload_material
from tests.support import Harness


class SnapshotServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()
        self.admin = self.h.user("admin-a", Role.INSTITUTION_ADMIN)
        self.admin_b = self.h.user("admin-b", Role.INSTITUTION_ADMIN,
                                   institution_id="inst-b")
        self.submitter = self.h.user("sub-a", Role.INSTITUTION_SUBMITTER)
        self.authority = self.h.user(
            "auth", Role.QUALITY_AUTHORITY, institution_id=None
        )
        self.auditor = self.h.user(
            "aud", Role.AUDITOR, institution_id=None
        )

    def tearDown(self) -> None:
        self.h.close()

    # ------------------------------------------------- 核心：冻结 + 不变
    def test_snapshot_freezes_filters_versions_and_summary(self) -> None:
        syllabus = upload_material(
            self.h, self.admin,
            kind=MaterialKind.SYLLABUS.value,
            data="大纲 v1".encode("utf-8"),
            title="课程大纲",
        )
        upload_material(
            self.h, self.admin,
            kind=MaterialKind.ENTERPRISE_FEEDBACK.value,
            data="敏感反馈 v1".encode("utf-8"),
            title="企业反馈",
            sensitivity=Sensitivity.SENSITIVE.value,
        )

        # 仅报送大纲类
        snap = self.h.ctx.snapshots.create_snapshot(
            self.admin, title="2026 秋报送",
            kinds=[MaterialKind.SYLLABUS.value],
        )
        sid = snap["snapshot_id"]
        self.assertEqual(snap["entry_count"], 1)
        self.assertEqual(
            snap["filters"],
            {"kinds": [MaterialKind.SYLLABUS.value], "sensitivity": None},
        )
        self.assertTrue(snap["fingerprint"].startswith("sha256:"))

        _, summary_bytes_1 = self.h.ctx.snapshots.download_summary(
            self.admin, snapshot_id=sid
        )
        summary_1 = json.loads(summary_bytes_1.decode("utf-8"))
        self.assertEqual(len(summary_1["items"]), 1)
        self.assertEqual(
            summary_1["items"][0]["version_id"],
            syllabus.version["version_id"],
        )
        self.assertEqual(
            summary_1["items"][0]["sha256"], syllabus.version["sha256"]
        )

        # ---- 源数据随后发生各种变化 ----
        v2 = self.h.ctx.evidence.upload_version(
            self.admin,
            material_id=syllabus.material["material_id"],
            data="大纲 v2：事后更新".encode("utf-8"),
        )
        # 新增一份符合筛选条件的新材料
        upload_material(
            self.h, self.admin,
            kind=MaterialKind.SYLLABUS.value,
            data="另一份大纲".encode("utf-8"),
            title="第二份大纲",
        )

        # 已报送快照的固定摘要一字节不变
        _, summary_bytes_2 = self.h.ctx.snapshots.download_summary(
            self.admin, snapshot_id=sid
        )
        self.assertEqual(summary_bytes_1, summary_bytes_2)
        stored = self.h.repo.get_snapshot(sid)
        self.assertEqual(stored.fingerprint, snap["fingerprint"])
        self.assertEqual(
            [e.version_id for e in stored.entries],
            [syllabus.version["version_id"]],
        )
        self.assertNotIn(v2["version_id"], [e.version_id for e in stored.entries])

        # 快照条目的内容字节取自冻结副本：仍是 v1
        meta, data, _ = self.h.ctx.snapshots.download_entry(
            self.admin,
            snapshot_id=sid,
            version_id=syllabus.version["version_id"],
        )
        self.assertEqual(data, "大纲 v1".encode("utf-8"))
        self.assertEqual(meta["sha256"], syllabus.version["sha256"])

    def test_snapshot_download_survives_source_blob_delete_and_tamper(self) -> None:
        item = upload_material(
            self.h, self.admin, data="报送原件 v1".encode("utf-8")
        )
        snap = self.h.ctx.snapshots.create_snapshot(self.admin, title="报送")
        sid = snap["snapshot_id"]
        vid = item.version["version_id"]
        sha = item.version["sha256"].split(":", 1)[1]

        # 直接改库：删除并篡改源 blobs
        self.h.repo._conn.execute("DELETE FROM blobs WHERE sha256 = ?", (sha,))
        _, data, _ = self.h.ctx.snapshots.download_entry(
            self.admin, snapshot_id=sid, version_id=vid
        )
        self.assertEqual(data, "报送原件 v1".encode("utf-8"))

        # 塞回一份不同字节（同 sha 不可能通过服务端，直接模拟库被改写）
        self.h.repo._conn.execute(
            "INSERT INTO blobs(sha256, data, media_type, size, created_at)"
            " VALUES(?,?,?,?,?)",
            (sha, b"tampered", "application/octet-stream", len(b"tampered"), ""),
        )
        _, data2, _ = self.h.ctx.snapshots.download_entry(
            self.admin, snapshot_id=sid, version_id=vid
        )
        self.assertEqual(data2, "报送原件 v1".encode("utf-8"))
        _, summary_bytes = self.h.ctx.snapshots.download_summary(
            self.admin, snapshot_id=sid
        )
        self.assertIn(sha, summary_bytes.decode("utf-8"))

    def test_sensitivity_filter_only_selects_sensitive(self) -> None:
        upload_material(self.h, self.admin, kind=MaterialKind.SYLLABUS.value,
                        data="普通大纲".encode("utf-8"))
        upload_material(
            self.h, self.admin,
            kind=MaterialKind.ENTERPRISE_FEEDBACK.value,
            data="敏感反馈".encode("utf-8"),
            sensitivity=Sensitivity.SENSITIVE.value,
        )
        snap = self.h.ctx.snapshots.create_snapshot(
            self.admin, title="敏感报送",
            sensitivity=Sensitivity.SENSITIVE.value,
        )
        self.assertEqual(snap["entry_count"], 1)
        self.assertEqual(snap["filters"]["sensitivity"], "sensitive")

    def test_filter_kinds_order_is_canonicalized(self) -> None:
        s1 = self.h.ctx.snapshots.create_snapshot(
            self.admin, title="A",
            kinds=[MaterialKind.FACULTY.value, MaterialKind.SYLLABUS.value],
        )
        s2 = self.h.ctx.snapshots.create_snapshot(
            self.admin, title="B",
            kinds=[MaterialKind.SYLLABUS.value, MaterialKind.FACULTY.value],
        )
        self.assertEqual(
            self.h.repo.get_snapshot(s1["snapshot_id"]).filters,
            self.h.repo.get_snapshot(s2["snapshot_id"]).filters,
        )

    def test_invalid_filters_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            self.h.ctx.snapshots.create_snapshot(
                self.admin, title="X", kinds=["not_a_kind"]
            )
        with self.assertRaises(ValidationError):
            self.h.ctx.snapshots.create_snapshot(
                self.admin, title="X", sensitivity="weird"
            )

    def test_empty_snapshot_is_still_frozen_and_verifies(self) -> None:
        snap = self.h.ctx.snapshots.create_snapshot(
            self.admin, title="空报送",
            kinds=[MaterialKind.ASSESSMENT.value],
        )
        self.assertEqual(snap["entry_count"], 0)
        self.h.ctx.close()
        report = verify_database(self.h.db_path)
        self.assertTrue(report.ok, report.failures)
        self.assertEqual(report.snapshot_count, 1)

    # ------------------------------------------------------------- 幂等
    def test_idempotent_replay_returns_first_snapshot_even_after_changes(self) -> None:
        item = upload_material(self.h, self.admin, data=b"v1")
        s1 = self.h.ctx.snapshots.create_snapshot(
            self.admin, title="报送", idempotency_key="report-2026q4"
        )
        # 源数据变化后用同一幂等键重发：必须回放首份快照
        self.h.ctx.evidence.upload_version(
            self.admin, material_id=item.material["material_id"], data=b"v2"
        )
        s2 = self.h.ctx.snapshots.create_snapshot(
            self.admin, title="报送", idempotency_key="report-2026q4"
        )
        self.assertTrue(s2["replayed"])
        self.assertEqual(s1["snapshot_id"], s2["snapshot_id"])
        self.assertEqual(s1["fingerprint"], s2["fingerprint"])

    # ------------------------------------------------------------- 权限
    def test_only_admin_authority_auditor_may_access(self) -> None:
        upload_material(self.h, self.admin, data=b"x")
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.snapshots.create_snapshot(
                self.submitter, title="无权报送"
            )
        snap = self.h.ctx.snapshots.create_snapshot(self.admin, title="报送")
        sid = snap["snapshot_id"]

        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.snapshots.get_snapshot(self.submitter, sid)
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.snapshots.get_snapshot(self.admin_b, sid)

        # 权威/审计可跨机构查看
        self.assertEqual(
            self.h.ctx.snapshots.get_snapshot(self.authority, sid)["snapshot_id"],
            sid,
        )
        self.assertEqual(
            self.h.ctx.snapshots.get_snapshot(self.auditor, sid)["snapshot_id"],
            sid,
        )
        # 权威机构没有所属机构，不能直接生成机构报送
        with self.assertRaises(PermissionDeniedError):
            self.h.ctx.snapshots.create_snapshot(self.authority, title="越权")
        # 列表：管理员只看本机构，权威/审计看全部
        self.assertEqual(
            [s["snapshot_id"] for s in
             self.h.ctx.snapshots.list_snapshots(self.admin_b)],
            [],
        )
        self.assertEqual(
            len(self.h.ctx.snapshots.list_snapshots(self.auditor)), 1
        )

    # --------------------------------------------------------- 离线核验
    def test_verification_detects_snapshot_tampering(self) -> None:
        item = upload_material(self.h, self.admin, data="原件".encode("utf-8"))
        snap = self.h.ctx.snapshots.create_snapshot(self.admin, title="报送")
        sid = snap["snapshot_id"]
        sha = item.version["sha256"].split(":", 1)[1]

        import sqlite3

        def tamper(sql: str, params=()) -> None:
            conn = sqlite3.connect(self.h.db_path)
            conn.execute(sql, params)
            conn.commit()
            conn.close()

        # 干净库通过
        self.h.ctx.close()
        self.assertTrue(verify_database(self.h.db_path).ok)

        # 篡改固定摘要
        tamper(
            "UPDATE report_snapshots SET summary_json = ? WHERE snapshot_id = ?",
            (json.dumps({"hacked": True}), sid),
        )
        report = verify_database(self.h.db_path)
        self.assertFalse(report.ok)
        self.assertIn(
            "snapshot_summary_fingerprint_mismatch",
            {f["kind"] for f in report.failures},
        )

        # 篡改冻结的版本集合（条目 sha）
        tamper(
            "UPDATE report_snapshot_entries SET sha256 = ? WHERE snapshot_id = ?",
            ("0" * 64, sid),
        )
        report = verify_database(self.h.db_path)
        self.assertIn(
            "snapshot_fingerprint_mismatch",
            {f["kind"] for f in report.failures},
        )

        # 删除内容副本
        tamper(
            "DELETE FROM report_snapshot_blobs WHERE snapshot_id = ? AND sha256 = ?",
            (sid, sha),
        )
        report = verify_database(self.h.db_path)
        self.assertIn(
            "snapshot_blob_copy_missing",
            {f["kind"] for f in report.failures},
        )


class SnapshotHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        from service_09252_006.api.http_api import HttpApiServer
        from tests.test_http_api import ApiClient

        self.h = Harness()
        self.server = HttpApiServer(
            self.h.ctx, host="127.0.0.1", port=0, bootstrap_token="boot"
        )
        self.server.start()
        host, port = self.server.address
        self.base = f"http://{host}:{port}"
        self.boot = ApiClient(self.base, bootstrap="boot")
        status, _ = self.boot.request(
            "POST", "/v1/admin/users",
            {"user_id": "admin-a", "roles": ["institution_admin"],
             "institution_id": "inst-a"},
        )
        self.assertEqual(status, 201)
        status, _ = self.boot.request(
            "POST", "/v1/admin/tokens",
            {"user_id": "admin-a", "token": "tok-admin"},
        )
        self.assertEqual(status, 201)
        self.admin = ApiClient(self.base, token="tok-admin")

    def tearDown(self) -> None:
        self.server.stop()
        self.h.close()

    def test_snapshot_flow_over_http(self) -> None:
        content = "HTTP 报送原件".encode("utf-8")
        status, mat = self.admin.request(
            "POST", "/v1/materials",
            {"kind": "syllabus", "title": "大纲"},
        )
        self.assertEqual(status, 201)
        status, ver = self.admin.request(
            "POST", f"/v1/materials/{mat['material_id']}/versions",
            {"content_base64": base64.b64encode(content).decode("ascii"),
             "media_type": "text/plain"},
        )
        self.assertEqual(status, 201)

        status, snap = self.admin.request(
            "POST", "/v1/snapshots",
            {"title": "HTTP 报送", "kinds": ["syllabus"]},
        )
        self.assertEqual(status, 201)
        sid = snap["snapshot_id"]

        status, body1, headers = self.admin.request(
            "GET", f"/v1/snapshots/{sid}/summary", raw=True
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["X-Snapshot-Id"], sid)
        self.assertEqual(
            headers["X-Snapshot-Fingerprint"], snap["fingerprint"]
        )

        # 源数据变化后，HTTP 下载的固定摘要仍字节一致
        self.admin.request(
            "POST", f"/v1/materials/{mat['material_id']}/versions",
            {"content_base64": base64.b64encode("v2 事后内容".encode("utf-8")).decode("ascii")},
        )
        status, body2, _ = self.admin.request(
            "GET", f"/v1/snapshots/{sid}/summary", raw=True
        )
        self.assertEqual(body1, body2)
        parsed = json.loads(body2.decode("utf-8"))
        self.assertEqual(parsed["items"][0]["version_id"], ver["version_id"])

        # 冻结条目内容下载
        status, data, headers = self.admin.request(
            "GET",
            f"/v1/snapshots/{sid}/entries/{ver['version_id']}/content",
            raw=True,
        )
        self.assertEqual(status, 200)
        self.assertEqual(data, content)
        self.assertEqual(headers["X-Content-Sha256"], ver["sha256"])


if __name__ == "__main__":
    unittest.main()
