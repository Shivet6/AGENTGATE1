"""Tests for AGENTGATE's policy-gated file-security layer."""
import os
import tempfile
import unittest
from pathlib import Path

from file_security import FileRequest, FileSecurity, FileSecurityError
from security_engine import Authenticator, SecurityEngine, SQLiteSecurityStore


class FileSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "files"
        self.root.mkdir()
        self.db = Path(self.temp.name) / "audit.db"
        self.auth = Authenticator("test-auth-secret-key-32-bytes-minimum")
        self.store = SQLiteSecurityStore(self.db, audit_key="test-audit-secret-key-32-bytes-minimum")
        self.store.set_session("session-1", "admin-user")
        self.context = self.auth.issue_context("admin-user", "session-1")
        self.engine = SecurityEngine(store=self.store, authenticator=self.auth)
        self.fs = FileSecurity(self.engine, self.root, max_file_bytes=1024)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def request(self, **kwargs):
        data = {"principal": "report-agent", "resource_id": "public-guide", "path": "note.txt"}
        data.update(kwargs)
        # Test fixture acts as the trusted setup/admin provisioning resource bindings.
        self.store.register_file_resource(data["resource_id"], data["path"])
        return data

    def test_write_and_read_roundtrip_hash(self):
        data = b"AGENTGATE file security"
        written = self.fs.write(self.request(), data, self.context)
        self.assertEqual(written.sha256, __import__("hashlib").sha256(data).hexdigest())
        read = self.fs.read(self.request(), self.context)
        self.assertEqual(read.content, data)
        self.assertTrue(self.fs.verify_sha256(read.content, read.sha256))
        self.assertFalse(self.fs.verify_sha256(b"tampered", read.sha256))

    def test_traversal_rejected(self):
        with self.assertRaises(Exception):
            FileRequest(**self.request(path="../outside.txt"))

    def test_absolute_path_rejected(self):
        with self.assertRaises(Exception):
            FileRequest(**self.request(path="/etc/passwd"))

    def test_symlink_rejected(self):
        outside = Path(self.temp.name) / "outside.txt"
        outside.write_text("secret")
        link = self.root / "link.txt"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(FileSecurityError):
            self.fs.read(self.request(path="link.txt"), self.context)

    def test_size_limit_rejected_before_write(self):
        with self.assertRaises(FileSecurityError):
            self.fs.write(self.request(), b"x" * 1025, self.context)
        self.assertFalse((self.root / "note.txt").exists())

    def test_missing_file_read_blocked(self):
        with self.assertRaises(FileSecurityError):
            self.fs.read(self.request(path="missing.txt"), self.context)

    def test_parent_directory_must_exist(self):
        with self.assertRaises(FileSecurityError):
            self.fs.write(self.request(path="newdir/note.txt"), b"x", self.context)

    def test_bad_context_blocks_write(self):
        with self.assertRaises(FileSecurityError):
            self.fs.write(self.request(), b"x", None)

    def test_extension_allowlist(self):
        restricted = FileSecurity(self.engine, self.root, allowed_extensions={"txt"})
        with self.assertRaises(FileSecurityError):
            restricted.write(self.request(path="note.exe"), b"x", self.context)

    def test_invalid_request_shape_rejected(self):
        with self.assertRaises(FileSecurityError):
            self.fs.read({"principal": "report-agent", "resource_id": "public-guide", "path": "note.txt", "admin": True}, self.context)

    def test_root_symlink_rejected(self):
        real = Path(self.temp.name) / "real-root"
        real.mkdir()
        link = Path(self.temp.name) / "root-link"
        try:
            link.symlink_to(real, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(ValueError):
            FileSecurity(self.engine, link)

    def test_resource_id_cannot_be_rebound_to_other_path(self):
        self.store.register_file_resource("bound-resource", "safe.txt")
        with self.assertRaises(FileSecurityError):
            self.fs.write({"principal": "report-agent", "resource_id": "bound-resource", "path": "other.txt"}, b"x", self.context)

    def test_final_file_failure_is_audited(self):
        req = self.request(path="blocked.exe")
        before = len(self.store.get_audit_events())
        with self.assertRaises(FileSecurityError):
            FileSecurity(self.engine, self.root, allowed_extensions={"txt"}).write(req, b"x", self.context)
        events = self.store.get_audit_events()[before:]
        self.assertTrue(any(e["code"] == "FILE_WRITE_BLOCKED" and e["decision"] == "BLOCK" for e in events))
        self.assertTrue(self.store.verify_audit_chain())

    def test_audit_chain_stays_valid(self):
        self.fs.write(self.request(), b"audited", self.context)
        self.assertTrue(self.store.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()
