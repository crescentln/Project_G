from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import stat
import tempfile
import unittest
import zipfile

from ruleset.scripts import verify_upstream_composite as VERIFIER


class ArtifactZipTests(unittest.TestCase):
    def write_zip(
        self,
        path: pathlib.Path,
        entries: list[tuple[str, bytes, int | None]],
    ) -> None:
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, payload, mode in entries:
                info = zipfile.ZipInfo(name)
                info.compress_type = zipfile.ZIP_DEFLATED
                if mode is not None:
                    info.create_system = 3
                    info.external_attr = mode << 16
                archive.writestr(info, payload)

    def verify(self, path: pathlib.Path) -> dict[str, bytes]:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        files, observed = VERIFIER.read_artifact_zip(
            path,
            expected_digest=f"sha256:{digest}",
            expected_size=path.stat().st_size,
        )
        self.assertEqual(observed, digest)
        return files

    def test_exact_regular_artifact_zip_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw) / "artifact.zip"
            self.write_zip(
                path,
                [
                    (
                        "upstream-isolation-composite-evidence.tar",
                        b"evidence",
                        stat.S_IFREG | 0o644,
                    ),
                    (
                        "upstream-isolation-composite-evidence.sha256",
                        b"checksum",
                        stat.S_IFREG | 0o644,
                    ),
                ],
            )
            files = self.verify(path)
            self.assertEqual(set(files), VERIFIER.ARTIFACT_FILES)

    def test_traversal_duplicate_extra_and_symlink_are_rejected(self) -> None:
        cases = {
            "traversal": [
                ("../upstream-isolation-composite-evidence.tar", b"x", None),
                ("upstream-isolation-composite-evidence.sha256", b"y", None),
            ],
            "extra": [
                ("upstream-isolation-composite-evidence.tar", b"x", None),
                ("extra", b"y", None),
            ],
            "symlink": [
                (
                    "upstream-isolation-composite-evidence.tar",
                    b"target",
                    stat.S_IFLNK | 0o777,
                ),
                ("upstream-isolation-composite-evidence.sha256", b"y", None),
            ],
        }
        for label, entries in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as raw:
                path = pathlib.Path(raw) / "artifact.zip"
                self.write_zip(path, entries)
                with self.assertRaises(VERIFIER.CompositeVerificationError):
                    self.verify(path)

        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw) / "artifact.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("upstream-isolation-composite-evidence.tar", b"x")
                archive.writestr("upstream-isolation-composite-evidence.tar", b"y")
            with self.assertRaises(VERIFIER.CompositeVerificationError):
                self.verify(path)

    def test_api_digest_and_size_are_enforced_before_reading_members(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = pathlib.Path(raw) / "artifact.zip"
            self.write_zip(
                path,
                [
                    ("upstream-isolation-composite-evidence.tar", b"x", None),
                    ("upstream-isolation-composite-evidence.sha256", b"y", None),
                ],
            )
            with self.assertRaises(VERIFIER.CompositeVerificationError):
                VERIFIER.read_artifact_zip(
                    path,
                    expected_digest="sha256:" + "0" * 64,
                    expected_size=path.stat().st_size,
                )
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaises(VERIFIER.CompositeVerificationError):
                VERIFIER.read_artifact_zip(
                    path,
                    expected_digest=f"sha256:{digest}",
                    expected_size=path.stat().st_size + 1,
                )


class AttestationTests(unittest.TestCase):
    def payload(self, *, run_id: int = 22, attempt: int = 1) -> bytes:
        repository = "owner/repo"
        workflow = ".github/workflows/source-discovery.yml"
        sha = "a" * 40
        digest = "b" * 64
        return json.dumps(
            [
                {
                    "verificationResult": {
                        "signature": {
                            "certificate": {
                                "subjectAlternativeName": (
                                    f"https://github.com/{repository}/{workflow}"
                                    "@refs/heads/main"
                                ),
                                "githubWorkflowSHA": sha,
                                "githubWorkflowRepository": repository,
                                "githubWorkflowRef": "refs/heads/main",
                                "buildSignerDigest": sha,
                                "runnerEnvironment": "github-hosted",
                                "sourceRepositoryDigest": sha,
                                "sourceRepositoryRef": "refs/heads/main",
                                "runInvocationURI": (
                                    f"https://github.com/{repository}/actions/runs/"
                                    f"{run_id}/attempts/{attempt}"
                                ),
                            }
                        },
                        "statement": {
                            "subject": [{"digest": {"sha256": digest}}]
                        },
                        "verifiedTimestamps": [
                            {
                                "type": "Tlog",
                                "timestamp": "2026-08-02T12:00:00Z",
                            }
                        ],
                    }
                }
            ],
            separators=(",", ":"),
        ).encode()

    def test_exact_run_attempt_is_bound(self) -> None:
        kwargs = {
            "label": "test attestation",
            "repository": "owner/repo",
            "workflow_path": ".github/workflows/source-discovery.yml",
            "source_sha": "a" * 40,
            "run_id": 22,
            "run_attempt": 1,
            "subject_sha256": "b" * 64,
        }
        self.assertEqual(
            VERIFIER.validate_attestation(self.payload(), **kwargs),
            "2026-08-02T12:00:00Z",
        )
        kwargs["run_attempt"] = 2
        with self.assertRaises(VERIFIER.CompositeVerificationError):
            VERIFIER.validate_attestation(self.payload(), **kwargs)


def make_cycle(
    *,
    run_id: int,
    artifact_id: int,
    started_epoch: int,
    changed: list[str] | None = None,
) -> VERIFIER.CycleEvidence:
    changed = list(changed or [])
    source = "a" * 40
    content = "b" * 64
    artifact = VERIFIER.ArtifactIdentity(
        name=f"ruleset-isolation-composite-v2-{source}-{content}-{'c' * 64}",
        source_sha=source,
        content_identity=content,
        evidence_sha256="c" * 64,
    )
    remote = VERIFIER.RemoteIdentity(
        repository="owner/repo",
        workflow_path=".github/workflows/source-discovery.yml",
        run_id=run_id,
        run_attempt=1,
        run_started_at=f"2026-08-02T12:{run_id:02d}:00Z",
        run_started_epoch=started_epoch,
        artifact_id=artifact_id,
        artifact_api_digest="sha256:" + "d" * 64,
        artifact_size=100,
        artifact_zip_sha256="d" * 64,
        inner_tlog_timestamp="2026-08-02T12:00:00Z",
        outer_tlog_timestamp="2026-08-02T12:00:01Z",
    )
    observation = {
        "blocker_count": run_id,
        "summary_sha256": str(run_id),
    }
    fetch = {"stable": True, "upstream_observation": observation}
    health = {"stable": True, "upstream_observation": observation}
    dist_files = {
        "fetch_report.json": VERIFIER.canonical_bytes(fetch),
        "source_health.json": VERIFIER.canonical_bytes(health),
        "index.json": b"stable",
    }
    identity = {
        "stable_selection_fingerprint": "e" * 64,
        "semantic_digest": "f" * 64,
        "selected_source_lock_sha256": "1" * 64,
        "category_lkg_anchor_sha256": "2" * 64,
        "dist_tree_sha256": str(run_id),
        "generated_at_utc": str(run_id),
        "isolation_observation_summary_sha256": str(run_id),
        "observation_evidence_identity": str(run_id),
        "review_sha256": str(run_id),
    }
    review = {
        "changed_categories": changed,
        "category_count": 2,
        "candidate_category_count": 1 if changed else 0,
        "published_lkg_category_count": 1 if changed else 2,
        "derived_category_count": 0,
        "dist_tree_sha256": str(run_id),
        "isolation_blocker_count": run_id,
        "isolation_observation_summary_sha256": str(run_id),
        "review_sha256": str(run_id),
        "held_categories": ["held"],
        "quarantined_categories": ["held"],
        "isolated_source_ids": ["held:0"],
    }
    return VERIFIER.CycleEvidence(
        artifact=artifact,
        remote=remote,
        cycle_dir=pathlib.Path("/nonexistent"),
        evidence_sha256="c" * 64,
        dist_archive_sha256="3" * 64,
        evidence_files={},
        identity=identity,
        review=review,
        gate={},
        automated_review={},
        isolation_artifact={},
        plan={"stable_selection": {"selection": "stable"}},
        lkg_binding={"binding": "stable"},
        containment_boundary_sha256="4" * 64,
        stable_payload_sha256="5" * 64,
        dist_files=dist_files,
        dist_manifest=[],
        candidate_manifest={},
        fetch_report=fetch,
        source_health=health,
    )


class PairTests(unittest.TestCase):
    def test_only_exact_observation_subtrees_may_change(self) -> None:
        previous = make_cycle(run_id=1, artifact_id=101, started_epoch=1_000)
        current = make_cycle(run_id=7, artifact_id=102, started_epoch=1_301)
        self.assertEqual(VERIFIER.validate_pair(current, previous), 301)

        changed = copy.deepcopy(current)
        changed.fetch_report["stable"] = False
        with self.assertRaises(VERIFIER.CompositeVerificationError):
            VERIFIER.validate_pair(changed, previous)

        changed = copy.deepcopy(current)
        changed.review["held_categories"] = ["different"]
        with self.assertRaises(VERIFIER.CompositeVerificationError):
            VERIFIER.validate_pair(changed, previous)

    def test_distinct_remote_identity_is_required(self) -> None:
        previous = make_cycle(run_id=1, artifact_id=101, started_epoch=1_000)
        current = make_cycle(run_id=1, artifact_id=102, started_epoch=1_301)
        with self.assertRaises(VERIFIER.CompositeVerificationError):
            VERIFIER.validate_pair(current, previous)
        current = make_cycle(run_id=7, artifact_id=101, started_epoch=1_301)
        with self.assertRaises(VERIFIER.CompositeVerificationError):
            VERIFIER.validate_pair(current, previous)

    def test_pair_receipt_never_grants_publication_authority(self) -> None:
        previous = make_cycle(run_id=1, artifact_id=101, started_epoch=1_000)
        noop = make_cycle(run_id=7, artifact_id=102, started_epoch=1_301)
        receipt = VERIFIER.build_pair_receipt(
            current=noop, previous=previous, cycle_separation_seconds=301
        )
        self.assertFalse(receipt["eligible"])
        self.assertFalse(receipt["publication_authority"])
        self.assertEqual(receipt["decision"], "NOOP_NOT_ELIGIBLE")

        changed_previous = make_cycle(
            run_id=1, artifact_id=101, started_epoch=1_000, changed=["ai"]
        )
        changed = make_cycle(
            run_id=7, artifact_id=102, started_epoch=1_301, changed=["ai"]
        )
        receipt = VERIFIER.build_pair_receipt(
            current=changed,
            previous=changed_previous,
            cycle_separation_seconds=301,
        )
        self.assertFalse(receipt["eligible"])
        self.assertFalse(receipt["publication_authority"])
        self.assertEqual(
            receipt["decision"], "REQUIRES_PROMOTION_AUTHORIZATION"
        )


if __name__ == "__main__":
    unittest.main()
