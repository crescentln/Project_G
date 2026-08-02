import base64
import hashlib
import importlib.util
import io
import json
import pathlib
import tarfile
import tempfile
import types
import unittest
from unittest import mock


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

    def verification_fixture(self, temp: pathlib.Path) -> tuple[types.SimpleNamespace, dict]:
        release_sha = "a" * 40
        main_sha = "b" * 40
        release_tree_sha = "c" * 40
        main_tree_sha = "d" * 40
        index_bytes = b'{"category_count":55}\n'
        index_blob = VERIFY.git_blob_sha(index_bytes)
        archive = temp / "ruleset-dist.tar.gz"
        with tarfile.open(archive, "w:gz") as bundle:
            member = tarfile.TarInfo("dist/index.json")
            member.size = len(index_bytes)
            bundle.addfile(member, io.BytesIO(index_bytes))
        checksum = temp / "ruleset-dist.sha256"
        archive_digest = VERIFY.sha256_file(archive)
        checksum.write_text(
            f"{archive_digest}  {archive.name}\n",
            encoding="utf-8",
        )
        tag = "ruleset-20260801T000000Z-test"
        repository = "crescentln/Project_G"
        readme = {"size": 0, "sha": VERIFY.EMPTY_BLOB_SHA}
        raw_index = {
            "content": base64.b64encode(index_bytes).decode("ascii")
        }
        status = {
            "context": "ruleset/published",
            "state": "success",
            "creator": {"login": "github-actions[bot]"},
            "avatar_url": "https://avatars.githubusercontent.com/in/15368?v=4",
            "target_url": f"https://github.com/{repository}/actions/runs/1234",
        }
        data = {
            f"repos/{repository}/commits/main": {"sha": main_sha},
            f"repos/{repository}/compare/{release_sha}...{main_sha}": {
                "status": "ahead"
            },
            f"repos/{repository}/git/ref/tags/{tag}": {
                "object": {"type": "commit", "sha": release_sha}
            },
            f"repos/{repository}/releases/tags/{tag}": {
                "tag_name": tag,
                "draft": False,
                "prerelease": False,
                "immutable": True,
                "assets": [
                    {
                        "name": archive.name,
                        "digest": f"sha256:{archive_digest}",
                    },
                    {
                        "name": checksum.name,
                        "digest": f"sha256:{VERIFY.sha256_file(checksum)}",
                    },
                ],
            },
            f"repos/{repository}/git/commits/{release_sha}": {
                "tree": {"sha": release_tree_sha}
            },
            f"repos/{repository}/git/trees/{release_tree_sha}?recursive=1": {
                "truncated": False,
                "tree": [
                    {
                        "path": "ruleset/dist/index.json",
                        "type": "blob",
                        "sha": index_blob,
                    }
                ],
            },
            f"repos/{repository}/git/commits/{main_sha}": {
                "tree": {"sha": main_tree_sha}
            },
            f"repos/{repository}/git/trees/{main_tree_sha}?recursive=1": {
                "truncated": False,
                "tree": [
                    {
                        "path": "ruleset/dist/index.json",
                        "type": "blob",
                        "sha": index_blob,
                    }
                ],
            },
            f"repos/{repository}/contents/README.md?ref={release_sha}": readme,
            f"repos/{repository}/contents/README.md?ref={main_sha}": readme,
            f"repos/{repository}/contents/ruleset/dist/index.json?ref={release_sha}": raw_index,
            f"repos/{repository}/contents/ruleset/dist/index.json?ref={main_sha}": raw_index,
            f"repos/{repository}/commits/{release_sha}/status": {
                "statuses": [status]
            },
            f"repos/{repository}/actions/runs/1234": {
                "status": "completed",
                "conclusion": "success",
                "path": ".github/workflows/ruleset-update.yml",
                "repository": {"full_name": repository},
            },
        }
        args = types.SimpleNamespace(
            repository=repository,
            sha=release_sha,
            main_sha=main_sha,
            tag=tag,
            archive=archive,
            checksum=checksum,
            skip_main=False,
            require_published_status=True,
        )
        return args, data

    def test_code_only_main_advance_is_valid_when_dist_tree_is_identical(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            args, data = self.verification_fixture(pathlib.Path(raw_temp))
            with mock.patch.object(VERIFY, "gh_json", side_effect=lambda path: data[path]):
                VERIFY.verify(args)

    def test_diverged_release_or_changed_main_dist_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            args, data = self.verification_fixture(pathlib.Path(raw_temp))
            compare_path = f"repos/{args.repository}/compare/{args.sha}...{args.main_sha}"
            data[compare_path] = {"status": "diverged"}
            with mock.patch.object(VERIFY, "gh_json", side_effect=lambda path: data[path]):
                with self.assertRaisesRegex(VERIFY.VerifyError, "not an ancestor"):
                    VERIFY.verify(args)

        with tempfile.TemporaryDirectory() as raw_temp:
            args, data = self.verification_fixture(pathlib.Path(raw_temp))
            main_tree = data[f"repos/{args.repository}/git/commits/{args.main_sha}"]["tree"]["sha"]
            data[f"repos/{args.repository}/git/trees/{main_tree}?recursive=1"]["tree"][0][
                "sha"
            ] = "e" * 40
            with mock.patch.object(VERIFY, "gh_json", side_effect=lambda path: data[path]):
                with self.assertRaisesRegex(VERIFY.VerifyError, "current main dist tree"):
                    VERIFY.verify(args)

    def test_latest_failed_publication_status_invalidates_older_success(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            args, data = self.verification_fixture(pathlib.Path(raw_temp))
            status_path = f"repos/{args.repository}/commits/{args.sha}/status"
            old_success = data[status_path]["statuses"][0]
            data[status_path]["statuses"] = [
                {**old_success, "state": "failure"},
                old_success,
            ]
            with mock.patch.object(VERIFY, "gh_json", side_effect=lambda path: data[path]):
                with self.assertRaisesRegex(VERIFY.VerifyError, "latest successful"):
                    VERIFY.verify(args)


if __name__ == "__main__":
    unittest.main()
