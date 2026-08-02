from __future__ import annotations

import copy
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


SCRIPT = (
    pathlib.Path(__file__).resolve().parents[1]
    / "scripts"
    / "build_category_lkg_binding.py"
)
SPEC = importlib.util.spec_from_file_location("build_category_lkg_binding", SCRIPT)
assert SPEC and SPEC.loader
BINDING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BINDING)


REPOSITORY = "owner/project"
MAIN_SHA = "f" * 40
RELEASE_SHA = "c3c4a5cf3a8f" + "1" * 28
TREE_OID = "d" * 40
SOURCE_SHA = "e" * 40
TAG = "ruleset-20260730T164904Z-c3c4a5cf3a8f"


def write_json(path: pathlib.Path, payload: object) -> None:
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")


def category_paths(category: str) -> dict[str, str]:
    return {
        field: template.format(category=category)
        for field, template in BINDING.CATEGORY_OUTPUT_PATH_TEMPLATES.items()
    }


class CategoryLkgBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp_dir.name)
        self.dist = self.root / "dist"
        (self.dist / "stash").mkdir(parents=True)
        (self.dist / "meta").mkdir()
        categories = []
        for priority, category in enumerate(("a", "b"), start=1):
            rules = [
                f"DOMAIN,{category}.example",
                f"DOMAIN-SUFFIX,{category}.example",
            ]
            (self.dist / "stash" / f"{category}.list").write_text(
                "\n".join(rules) + "\n", encoding="utf-8"
            )
            write_json(self.dist / "meta" / f"{category}.json", {"id": category})
            output_paths = category_paths(category)
            for field, raw_path in output_paths.items():
                if field == "stash_path":
                    continue
                path = self.dist / raw_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"{field}:{category}\n", encoding="utf-8")
            categories.append(
                {
                    "id": category,
                    "rule_count": len(rules),
                    "recommended_action": "PROXY",
                    "recommended_priority": priority,
                    "contract": {"category": category, "action": "PROXY"},
                    **output_paths,
                }
            )
        write_json(
            self.dist / "index.json",
            {"category_count": len(categories), "categories": categories},
        )
        source_lock = {"version": 1, "repositories": {}}
        write_json(self.dist / "sources.lock.json", source_lock)
        source_lock_sha256 = BINDING.source_lock_identity(
            source_lock, "test"
        )[0]
        write_json(
            self.dist / "source_provenance.json",
            {
                "source_count": 0,
                "source_lock_sha256": source_lock_sha256,
                "sources": [],
            },
        )
        write_json(
            self.dist / "candidate_manifest.json",
            {
                "source_commit_sha": SOURCE_SHA,
                "semantic_digest": "3" * 64,
                "source_lock_sha256": source_lock_sha256,
            },
        )

        self.archive = self.root / "ruleset-dist.tar.gz"
        with tarfile.open(self.archive, "w:gz") as archive:
            archive.add(self.dist, arcname="dist")
        self.archive_sha256 = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.checksum = self.root / "ruleset-dist.sha256"
        self.checksum.write_text(
            f"{self.archive_sha256}  ruleset-dist.tar.gz\n", encoding="utf-8"
        )
        checksum_sha256 = hashlib.sha256(self.checksum.read_bytes()).hexdigest()

        self.release = {
            "id": 123,
            "tag_name": TAG,
            "immutable": True,
            "draft": False,
            "prerelease": False,
            "published_at": "2026-07-30T16:49:18Z",
            "assets": [
                {
                    "id": 456,
                    "name": "ruleset-dist.tar.gz",
                    "size": self.archive.stat().st_size,
                    "digest": f"sha256:{self.archive_sha256}",
                },
                {
                    "id": 457,
                    "name": "ruleset-dist.sha256",
                    "size": self.checksum.stat().st_size,
                    "digest": f"sha256:{checksum_sha256}",
                },
            ],
        }
        self.release_path = self.root / "release.json"
        write_json(self.release_path, self.release)

        repository_url = f"https://github.com/{REPOSITORY}"
        workflow_path = ".github/workflows/source-discovery.yml"
        self.attestation = [
            {
                "verificationResult": {
                    "statement": {
                        "subject": [
                            {
                                "name": "ruleset-dist.tar.gz",
                                "digest": {"sha256": self.archive_sha256},
                            }
                        ],
                        "predicateType": "https://slsa.dev/provenance/v1",
                        "predicate": {
                            "buildDefinition": {
                                "externalParameters": {
                                    "workflow": {
                                        "path": workflow_path,
                                        "ref": "refs/heads/main",
                                        "repository": repository_url,
                                    }
                                },
                                "resolvedDependencies": [
                                    {
                                        "uri": f"git+{repository_url}@refs/heads/main",
                                        "digest": {"gitCommit": SOURCE_SHA},
                                    }
                                ],
                            },
                            "runDetails": {
                                "metadata": {
                                    "invocationId": (
                                        f"{repository_url}/actions/runs/789/attempts/1"
                                    )
                                }
                            },
                        },
                    },
                    "signature": {
                        "certificate": {
                            "issuer": "https://token.actions.githubusercontent.com",
                            "subjectAlternativeName": (
                                f"{repository_url}/{workflow_path}@refs/heads/main"
                            ),
                            "githubWorkflowRepository": REPOSITORY,
                            "githubWorkflowRef": "refs/heads/main",
                            "sourceRepositoryURI": repository_url,
                            "sourceRepositoryRef": "refs/heads/main",
                            "sourceRepositoryDigest": SOURCE_SHA,
                        }
                    },
                }
            }
        ]
        self.attestation_path = self.root / "attestation.json"
        write_json(self.attestation_path, self.attestation)

        self.status = {
            "sha": RELEASE_SHA,
            "statuses": [
                {
                    "id": 998,
                    "context": "ruleset/gate",
                    "state": "success",
                    "description": BINDING.PUBLICATION_STATUS_DESCRIPTIONS[
                        "ruleset/gate"
                    ],
                    "avatar_url": "https://avatars.githubusercontent.com/in/15368?v=4",
                    "target_url": f"{repository_url}/actions/runs/987",
                    "updated_at": "2026-07-30T16:49:40Z",
                },
                {
                    "id": 999,
                    "context": "ruleset/published",
                    "state": "success",
                    "description": BINDING.PUBLICATION_STATUS_DESCRIPTIONS[
                        "ruleset/published"
                    ],
                    "avatar_url": "https://avatars.githubusercontent.com/in/15368?v=4",
                    "target_url": f"{repository_url}/actions/runs/987",
                    "updated_at": "2026-07-30T16:49:47Z",
                }
            ],
        }
        self.status_path = self.root / "status.json"
        write_json(self.status_path, self.status)
        self.publication_receipt = {
            "schema": BINDING.PUBLISHED_RECEIPT_SCHEMA,
            "repository": REPOSITORY,
            "release_commit_sha": RELEASE_SHA,
            "main_sha": MAIN_SHA,
            "release_id": 123,
            "release_tag": TAG,
            "candidate_source_sha": SOURCE_SHA,
            "release_parent_sha": SOURCE_SHA,
            "archive_sha256": self.archive_sha256,
            "checksum_sha256": checksum_sha256,
            "dist_tree_sha256": "4" * 64,
            "dist_file_count": len(BINDING.directory_manifest(self.dist)),
            "category_count": 2,
            "publication_statuses": {
                "ruleset/gate": {
                    "status_id": 998,
                    "context": "ruleset/gate",
                    "state": "success",
                    "description": BINDING.PUBLICATION_STATUS_DESCRIPTIONS[
                        "ruleset/gate"
                    ],
                    "github_actions_app_id": 15368,
                    "target_url": f"{repository_url}/actions/runs/987",
                    "run_id": 987,
                    "run_attempt": 1,
                    "run_head_sha": SOURCE_SHA,
                    "updated_at": "2026-07-30T16:49:40Z",
                },
                "ruleset/published": {
                    "status_id": 999,
                    "context": "ruleset/published",
                    "state": "success",
                    "description": BINDING.PUBLICATION_STATUS_DESCRIPTIONS[
                        "ruleset/published"
                    ],
                    "github_actions_app_id": 15368,
                    "target_url": f"{repository_url}/actions/runs/987",
                    "run_id": 987,
                    "run_attempt": 1,
                    "run_head_sha": SOURCE_SHA,
                    "updated_at": "2026-07-30T16:49:47Z",
                },
            },
        }
        self.publication_receipt["receipt_sha256"] = BINDING.digest_payload(
            self.publication_receipt
        )
        self.publication_receipt_path = self.root / "published-receipt.json"
        write_json(self.publication_receipt_path, self.publication_receipt)
        self.source_config = self.root / "sources.json"
        write_json(
            self.source_config,
            {"categories": [{"id": "a"}, {"id": "b"}]},
        )
        self.source_config_blob_oid = BINDING.git_blob_oid(self.source_config)
        self.source_registry = self.root / "source-registry.json"
        write_json(self.source_registry, {"schema": "test-source-registry-v1"})
        self.source_registry_blob_oid = BINDING.git_blob_oid(
            self.source_registry
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def args(self, **overrides: object) -> types.SimpleNamespace:
        values = {
            "repository": REPOSITORY,
            "main_sha": MAIN_SHA,
            "release_json": self.release_path,
            "release_commit_sha": RELEASE_SHA,
            "release_dist_tree_oid": TREE_OID,
            "main_dist_tree_oid": TREE_OID,
            "candidate_source_config": self.source_config,
            "candidate_source_config_blob_oid": self.source_config_blob_oid,
            "release_source_config": self.source_config,
            "release_source_config_blob_oid": self.source_config_blob_oid,
            "main_source_config": self.source_config,
            "main_source_config_blob_oid": self.source_config_blob_oid,
            "candidate_source_registry": self.source_registry,
            "candidate_source_registry_blob_oid": self.source_registry_blob_oid,
            "release_source_registry": self.source_registry,
            "release_source_registry_blob_oid": self.source_registry_blob_oid,
            "main_source_registry": self.source_registry,
            "main_source_registry_blob_oid": self.source_registry_blob_oid,
            "archive": self.archive,
            "checksum": self.checksum,
            "baseline_dist": self.dist,
            "attestation_json": self.attestation_path,
            "published_status_json": self.status_path,
            "published_receipt_json": self.publication_receipt_path,
        }
        values.update(overrides)
        return types.SimpleNamespace(**values)

    def test_builds_deterministic_complete_category_binding(self) -> None:
        first = BINDING.build_binding(self.args())
        second = BINDING.build_binding(self.args())
        self.assertEqual(BINDING.canonical_bytes(first), BINDING.canonical_bytes(second))
        self.assertEqual(first["schema"], BINDING.BINDING_SCHEMA)
        self.assertFalse(first["enforcement_ready"])
        self.assertFalse(first["per_source_lkg_available"])
        self.assertTrue(first["source_config_unchanged_since_release"])
        self.assertTrue(first["source_config_candidate_release_main_bound"])
        self.assertTrue(first["source_registry_candidate_release_main_bound"])
        self.assertFalse(first["legacy_provenance_exception"]["active"])
        self.assertEqual(
            first["source_config_blob_oid"], self.source_config_blob_oid
        )
        self.assertEqual(first["category_count"], 2)
        self.assertEqual(
            [item["category"] for item in first["categories"]], ["a", "b"]
        )
        self.assertEqual(
            first["lkg_anchor"]["source_attestation"]["source_sha"],
            SOURCE_SHA,
        )
        self.assertEqual(
            first["lkg_anchor"]["publication_receipt"][
                "publication_statuses"
            ]["ruleset/published"]["status_id"],
            999,
        )

    def test_rejects_release_and_main_dist_tree_drift(self) -> None:
        with self.assertRaisesRegex(
            BINDING.CategoryLkgBindingError, "does not match"
        ):
            BINDING.build_binding(self.args(main_dist_tree_oid="1" * 40))

    def test_rejects_release_and_main_source_config_drift(self) -> None:
        changed = self.root / "changed-sources.json"
        write_json(changed, {"categories": [{"id": "changed"}]})
        with self.assertRaisesRegex(
            BINDING.CategoryLkgBindingError, "do not match"
        ):
            BINDING.build_binding(
                self.args(
                    main_source_config=changed,
                    main_source_config_blob_oid=BINDING.git_blob_oid(changed),
                )
            )

    def test_rejects_release_and_main_source_registry_drift(self) -> None:
        changed = self.root / "changed-source-registry.json"
        write_json(changed, {"schema": "changed-source-registry-v1"})
        with self.assertRaisesRegex(
            BINDING.CategoryLkgBindingError, "do not match"
        ):
            BINDING.build_binding(
                self.args(
                    main_source_registry=changed,
                    main_source_registry_blob_oid=BINDING.git_blob_oid(changed),
                )
            )

    def test_legacy_provenance_derivation_is_exact_archive_allowlisted(self) -> None:
        source_config = {
            "categories": [
                {
                    "id": "a",
                    "sources": [
                        {
                            "type": "local_domain",
                            "path": "manual/categories/a.txt",
                            "authority": "owner-controlled",
                        }
                    ],
                }
            ]
        }
        bindings = BINDING.canonical_source_bindings(source_config)["bindings"]
        source_id = next(iter(bindings))
        provenance = {"sources": [{"source_id": source_id}]}
        archive_sha256 = "1" * 64
        with self.assertRaisesRegex(
            BINDING.CategoryLkgBindingError, "exact legacy allowlist"
        ):
            BINDING.legacy_provenance_derivations(
                source_config=source_config,
                provenance=provenance,
                archive_sha256=archive_sha256,
            )
        with mock.patch.object(
            BINDING,
            "LEGACY_PROVENANCE_ARCHIVE_ALLOWLIST",
            {archive_sha256},
        ):
            exception = BINDING.legacy_provenance_derivations(
                source_config=source_config,
                provenance=provenance,
                archive_sha256=archive_sha256,
            )
        self.assertTrue(exception["active"])
        self.assertEqual(exception["derived_source_count"], 1)
        self.assertEqual(exception["derived_sources"][0]["source_id"], source_id)

    def test_rejects_published_status_changed_after_verification(self) -> None:
        changed = copy.deepcopy(self.status)
        changed["statuses"][1]["id"] = 1000
        changed_path = self.root / "changed-status.json"
        write_json(changed_path, changed)
        with self.assertRaisesRegex(
            BINDING.CategoryLkgBindingError,
            "receipt differs from current status evidence",
        ):
            BINDING.build_binding(
                self.args(published_status_json=changed_path)
            )

    def test_rejects_archive_path_escape(self) -> None:
        unsafe = self.root / "unsafe.tar.gz"
        with tarfile.open(unsafe, "w:gz") as archive:
            member = tarfile.TarInfo("../escape")
            payload = b"escape"
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
        unsafe_digest = hashlib.sha256(unsafe.read_bytes()).hexdigest()
        unsafe_checksum = self.root / "unsafe.sha256"
        unsafe_checksum.write_text(
            f"{unsafe_digest}  ruleset-dist.tar.gz\n", encoding="utf-8"
        )
        unsafe_release = copy.deepcopy(self.release)
        unsafe_release["assets"][0]["digest"] = f"sha256:{unsafe_digest}"
        unsafe_release["assets"][0]["size"] = unsafe.stat().st_size
        unsafe_release["assets"][1]["digest"] = (
            "sha256:" + hashlib.sha256(unsafe_checksum.read_bytes()).hexdigest()
        )
        unsafe_release["assets"][1]["size"] = unsafe_checksum.stat().st_size
        unsafe_release_path = self.root / "unsafe-release.json"
        write_json(unsafe_release_path, unsafe_release)
        with self.assertRaisesRegex(
            BINDING.CategoryLkgBindingError, "unsafe archive member"
        ):
            BINDING.build_binding(
                self.args(
                    archive=unsafe,
                    checksum=unsafe_checksum,
                    release_json=unsafe_release_path,
                )
            )

    def test_rejects_unverified_attestation_identity(self) -> None:
        tampered = copy.deepcopy(self.attestation)
        tampered[0]["verificationResult"]["signature"]["certificate"][
            "sourceRepositoryURI"
        ] = "https://github.com/attacker/project"
        path = self.root / "tampered-attestation.json"
        write_json(path, tampered)
        with self.assertRaisesRegex(
            BINDING.CategoryLkgBindingError, "no verified Source Discovery"
        ):
            BINDING.build_binding(self.args(attestation_json=path))

    def test_rejects_attestation_source_not_bound_by_archive_manifest(self) -> None:
        tampered = copy.deepcopy(self.attestation)
        alternate_source_sha = "9" * 40
        result = tampered[0]["verificationResult"]
        result["statement"]["predicate"]["buildDefinition"][
            "resolvedDependencies"
        ][0]["digest"]["gitCommit"] = alternate_source_sha
        result["signature"]["certificate"][
            "sourceRepositoryDigest"
        ] = alternate_source_sha
        path = self.root / "alternate-source-attestation.json"
        write_json(path, tampered)
        with self.assertRaisesRegex(
            BINDING.CategoryLkgBindingError, "no verified Source Discovery"
        ):
            BINDING.build_binding(self.args(attestation_json=path))

    def test_rejects_cross_category_path_swap_with_equal_rule_counts(self) -> None:
        index = json.loads((self.dist / "index.json").read_text(encoding="utf-8"))
        first = index["categories"][0]["stash_path"]
        second = index["categories"][1]["stash_path"]
        index["categories"][0]["stash_path"] = second
        index["categories"][1]["stash_path"] = first
        with self.assertRaisesRegex(
            BINDING.CategoryLkgBindingError, "noncanonical"
        ):
            BINDING.category_output_identities(self.dist, index)

    def test_rejects_unowned_category_output(self) -> None:
        (self.dist / "stash" / "orphan.list").write_text(
            "DOMAIN,orphan.example\n", encoding="utf-8"
        )
        index = json.loads((self.dist / "index.json").read_text(encoding="utf-8"))
        with self.assertRaisesRegex(
            BINDING.CategoryLkgBindingError, "ownership is not exact"
        ):
            BINDING.category_output_identities(self.dist, index)

    def test_rejects_source_provenance_lock_digest_mismatch(self) -> None:
        payload = json.loads(
            (self.dist / "source_provenance.json").read_text(encoding="utf-8")
        )
        with self.assertRaisesRegex(
            BINDING.CategoryLkgBindingError, "identity is inconsistent"
        ):
            BINDING.validate_source_provenance(
                payload,
                "8" * 64,
                {},
            )

    def test_rejects_baseline_archive_content_drift(self) -> None:
        (self.dist / "stash" / "a.list").write_text(
            "DOMAIN,a.changed.example\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(
            BINDING.CategoryLkgBindingError, "do not match"
        ):
            BINDING.build_binding(self.args())


if __name__ == "__main__":
    unittest.main()
