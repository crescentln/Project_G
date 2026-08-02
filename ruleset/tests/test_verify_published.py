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
        source_sha = "e" * 40
        index_bytes = b'{"category_count":55}\n'
        index_blob = VERIFY.git_blob_sha(index_bytes)
        manifest_bytes = json.dumps(
            {"source_commit_sha": source_sha}, sort_keys=True
        ).encode("utf-8") + b"\n"
        manifest_blob = VERIFY.git_blob_sha(manifest_bytes)
        archive = temp / "ruleset-dist.tar.gz"
        with tarfile.open(archive, "w:gz") as bundle:
            for name, payload in (
                ("dist/index.json", index_bytes),
                ("dist/candidate_manifest.json", manifest_bytes),
            ):
                member = tarfile.TarInfo(name)
                member.size = len(payload)
                bundle.addfile(member, io.BytesIO(payload))
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
            "id": 5678,
            "context": "ruleset/published",
            "state": "success",
            "description": VERIFY.PUBLICATION_STATUS_DESCRIPTIONS[
                "ruleset/published"
            ],
            "creator": {"login": "github-actions[bot]"},
            "avatar_url": "https://avatars.githubusercontent.com/in/15368?v=4",
            "target_url": f"https://github.com/{repository}/actions/runs/1234",
            "updated_at": "2026-08-01T00:00:00Z",
        }
        gate_status = {
            **status,
            "id": 5677,
            "context": "ruleset/gate",
            "description": VERIFY.PUBLICATION_STATUS_DESCRIPTIONS[
                "ruleset/gate"
            ],
            "updated_at": "2026-08-01T00:00:00Z",
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
                "id": 9876,
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
                "tree": {"sha": release_tree_sha},
                "parents": [{"sha": source_sha}],
            },
            f"repos/{repository}/git/trees/{release_tree_sha}?recursive=1": {
                "truncated": False,
                "tree": [
                    {
                        "path": "ruleset/dist/index.json",
                        "type": "blob",
                        "sha": index_blob,
                    },
                    {
                        "path": "ruleset/dist/candidate_manifest.json",
                        "type": "blob",
                        "sha": manifest_blob,
                    },
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
                    },
                    {
                        "path": "ruleset/dist/candidate_manifest.json",
                        "type": "blob",
                        "sha": manifest_blob,
                    },
                ],
            },
            f"repos/{repository}/contents/README.md?ref={release_sha}": readme,
            f"repos/{repository}/contents/README.md?ref={main_sha}": readme,
            f"repos/{repository}/contents/ruleset/dist/index.json?ref={release_sha}": raw_index,
            f"repos/{repository}/contents/ruleset/dist/index.json?ref={main_sha}": raw_index,
            f"repos/{repository}/commits/{release_sha}/status": {
                "statuses": [gate_status, status]
            },
            f"repos/{repository}/actions/runs/1234": {
                "status": "completed",
                "conclusion": "success",
                "path": ".github/workflows/ruleset-update.yml",
                "head_sha": source_sha,
                "run_attempt": 1,
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
                receipt = VERIFY.verify(args)
            self.assertEqual(receipt["schema"], VERIFY.RECEIPT_SCHEMA)
            self.assertEqual(
                receipt["publication_statuses"]["ruleset/published"]["run_id"],
                1234,
            )
            self.assertEqual(
                receipt["publication_statuses"]["ruleset/gate"]["run_head_sha"],
                receipt["candidate_source_sha"],
            )
            self.assertEqual(
                receipt["release_parent_sha"], receipt["candidate_source_sha"]
            )

    def test_publication_run_must_target_the_candidate_source(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            args, data = self.verification_fixture(pathlib.Path(raw_temp))
            data[f"repos/{args.repository}/actions/runs/1234"]["head_sha"] = "9" * 40
            with mock.patch.object(VERIFY, "gh_json", side_effect=lambda path: data[path]):
                with self.assertRaisesRegex(VERIFY.VerifyError, "successful promotion"):
                    VERIFY.verify(args)

    def test_publication_statuses_must_resolve_to_the_same_run(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            args, data = self.verification_fixture(pathlib.Path(raw_temp))
            status_path = f"repos/{args.repository}/commits/{args.sha}/status"
            data[status_path]["statuses"][1]["target_url"] = (
                f"https://github.com/{args.repository}/actions/runs/9999"
            )
            with mock.patch.object(
                VERIFY, "gh_json", side_effect=lambda path: data[path]
            ):
                with self.assertRaisesRegex(VERIFY.VerifyError, "different runs"):
                    VERIFY.verify(args)

    def test_malformed_latest_status_id_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            args, data = self.verification_fixture(pathlib.Path(raw_temp))
            status_path = f"repos/{args.repository}/commits/{args.sha}/status"
            data[status_path]["statuses"][1]["id"] = "not-an-integer"
            with mock.patch.object(
                VERIFY, "gh_json", side_effect=lambda path: data[path]
            ):
                with self.assertRaisesRegex(VERIFY.VerifyError, "identity is invalid"):
                    VERIFY.verify(args)

    def test_release_commit_must_directly_descend_from_candidate_source(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            args, data = self.verification_fixture(pathlib.Path(raw_temp))
            data[f"repos/{args.repository}/git/commits/{args.sha}"]["parents"] = [
                {"sha": "9" * 40}
            ]
            with mock.patch.object(VERIFY, "gh_json", side_effect=lambda path: data[path]):
                with self.assertRaisesRegex(VERIFY.VerifyError, "unique parent"):
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
            published = data[status_path]["statuses"][1]
            data[status_path]["statuses"] = [
                old_success,
                published,
                {**published, "id": published["id"] + 1, "state": "failure"},
            ]
            with mock.patch.object(VERIFY, "gh_json", side_effect=lambda path: data[path]):
                with self.assertRaisesRegex(VERIFY.VerifyError, "latest successful"):
                    VERIFY.verify(args)

    def test_latest_failed_gate_status_invalidates_published_success(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            args, data = self.verification_fixture(pathlib.Path(raw_temp))
            status_path = f"repos/{args.repository}/commits/{args.sha}/status"
            gate, published = data[status_path]["statuses"]
            data[status_path]["statuses"] = [
                gate,
                published,
                {**gate, "id": gate["id"] + 1, "state": "failure"},
            ]
            with mock.patch.object(VERIFY, "gh_json", side_effect=lambda path: data[path]):
                with self.assertRaisesRegex(VERIFY.VerifyError, "ruleset/gate"):
                    VERIFY.verify(args)


if __name__ == "__main__":
    unittest.main()
