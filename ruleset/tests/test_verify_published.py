import hashlib
import importlib.util
import io
import pathlib
import tarfile
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "verify_published.py"
SPEC = importlib.util.spec_from_file_location("verify_published", SCRIPT)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class VerifyPublishedTests(unittest.TestCase):
    def test_archive_tree_uses_git_blob_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = pathlib.Path(temp_dir) / "ruleset-dist.tar.gz"
            payload = b'{"category_count": 55}\n'
            with tarfile.open(archive_path, "w:gz") as archive:
                member = tarfile.TarInfo("dist/index.json")
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
            tree = VERIFY.archive_dist_tree(archive_path)
        expected = hashlib.sha1(
            f"blob {len(payload)}\0".encode("ascii") + payload
        ).hexdigest()
        self.assertEqual(tree, {"index.json": expected})

    def test_archive_tree_rejects_duplicate_members(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = pathlib.Path(temp_dir) / "ruleset-dist.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                for payload in (b"first", b"second"):
                    member = tarfile.TarInfo("dist/index.json")
                    member.size = len(payload)
                    archive.addfile(member, io.BytesIO(payload))
            with self.assertRaisesRegex(VERIFY.VerifyError, "duplicate"):
                VERIFY.archive_dist_tree(archive_path)


if __name__ == "__main__":
    unittest.main()
