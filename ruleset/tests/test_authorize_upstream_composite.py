from __future__ import annotations

import copy
import unittest

from ruleset.scripts import authorize_upstream_composite as authorizer
from ruleset.scripts import verify_upstream_composite as verifier


SHA = "a" * 40
DIGEST = "b" * 64


def remote_cycle(run_id: int, artifact_id: int) -> dict[str, object]:
    return {
        "run_id": run_id,
        "run_attempt": 1,
        "artifact_id": artifact_id,
        "artifact_api_digest": f"sha256:{DIGEST}",
        "artifact_zip_sha256": DIGEST,
        "outer_evidence_sha256": DIGEST,
        "dist_archive_sha256": DIGEST,
        "dist_tree_sha256": DIGEST,
        "observation_evidence_identity": DIGEST,
        "inner_attestation_tlog_timestamp": "2026-08-02T12:00:00Z",
        "outer_attestation_tlog_timestamp": "2026-08-02T12:00:01Z",
    }


def authorization_pair() -> dict[str, object]:
    payload: dict[str, object] = {
        "schema": authorizer.PAIR_SCHEMA,
        "eligible": False,
        "publication_authority": False,
        "decision": "REQUIRES_PROMOTION_AUTHORIZATION",
        "source_sha": SHA,
        "minimum_cycle_separation_seconds": 300,
        "cycle_separation_seconds": 301,
        "allowed_cycle_variant_dist_files": sorted(verifier.VOLATILE_DIST_FILES),
        "changed_categories": ["alpha"],
        "changed_category_count": 1,
        "candidate_category_count": 1,
        "derived_category_count": 0,
        "current": remote_cycle(20, 200),
        "previous": remote_cycle(10, 100),
    }
    payload["receipt_sha256"] = verifier.digest_payload(payload)
    return payload


class PairAuthorizationTests(unittest.TestCase):
    def test_shadow_pair_requires_separate_positive_authorization(self) -> None:
        pair = authorization_pair()
        digest = authorizer.validate_pair_receipt(
            pair,
            repository="crescentln/Project_G",
            expected_main_sha=SHA,
        )
        self.assertEqual(digest, pair["receipt_sha256"])
        self.assertIs(pair["eligible"], False)
        self.assertIs(pair["publication_authority"], False)

    def test_semantic_noop_pair_cannot_enter_positive_authorization(self) -> None:
        pair = authorization_pair()
        pair["decision"] = "NOOP_NOT_ELIGIBLE"
        pair["changed_categories"] = []
        pair["changed_category_count"] = 0
        pair["receipt_sha256"] = verifier.digest_payload(
            {key: value for key, value in pair.items() if key != "receipt_sha256"}
        )
        with self.assertRaisesRegex(
            authorizer.CompositeAuthorizationError,
            "not authorization-ready",
        ):
            authorizer.validate_pair_receipt(
                pair,
                repository="crescentln/Project_G",
                expected_main_sha=SHA,
            )


class SelectedProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rows = [
            {
                "source_id": "alpha:https-source",
                "snapshot_origin": "observed-candidate",
                "authority": "official",
                "license": "Example-License",
                "owner": "example/source",
                "used_cache": False,
                "cache_mode": "network",
                "requested_refs": ["https://example.invalid/source.txt"],
                "resolved_ref": "https://example.invalid/source.txt",
                "limits": {"allowed_hosts": ["example.invalid"]},
                "content_sha256": "c" * 64,
            },
            {
                "source_id": "direct:aggregate",
                "snapshot_origin": "derived-composite",
                "type": "aggregate",
                "authority": "owner-controlled",
                "license": "inherits-components",
                "owner": "crescentln",
                "revision_strategy": "derived-from-locked-components",
                "used_cache": False,
                "cache_mode": "aggregate",
                "components": ["alpha", "beta"],
                "content_sha256": "d" * 64,
            },
            {
                "source_id": "direct:manual-overlay",
                "snapshot_origin": "exact-main-overlay",
                "type": "local_domain",
                "authority": "owner-controlled",
                "license": "owner-controlled",
                "owner": "crescentln",
                "revision_strategy": "local-content-sha256",
                "used_cache": False,
                "cache_mode": "local",
                "requested_refs": ["manual/categories/direct.txt"],
                "resolved_ref": "manual/categories/direct.txt",
                "content_sha256": "e" * 64,
            },
            {
                "source_id": "beta:published-source",
                "snapshot_origin": "published-lkg",
            },
        ]
        self.provenance = {
            "source_count": len(self.rows),
            "source_lock_sha256": DIGEST,
            "sources": self.rows,
        }
        self.identity = {
            "selected_source_lock_sha256": DIGEST,
            "selected_source_provenance_sha256": verifier.digest_payload(
                self.provenance
            ),
        }
        self.registry = {
            "authority_profiles": {
                "official": {
                    "license": "Example-License",
                    "owner": "example/source",
                    "no_cache_publish": True,
                    "revision_strategy": "https-validators-and-content-sha256",
                    "allowed_hosts": ["example.invalid"],
                },
                "owner-controlled": {
                    "license": "owner-controlled",
                    "owner": "crescentln",
                    "no_cache_publish": False,
                    "revision_strategy": "local-content-sha256",
                    "allowed_hosts": [],
                }
            }
        }

    def validate(
        self,
        provenance: dict[str, object],
        selected_categories: list[str] | None = None,
    ) -> tuple[int, int]:
        identity = copy.deepcopy(self.identity)
        identity["selected_source_provenance_sha256"] = verifier.digest_payload(
            provenance
        )
        return authorizer.validate_selected_provenance(
            dist_files={
                "source_provenance.json": verifier.canonical_bytes(provenance)
            },
            identity=identity,
            source_registry=self.registry,
            selected_candidate_categories=(
                ["alpha"] if selected_categories is None else selected_categories
            ),
        )

    def test_accepted_slice_allows_only_bound_non_network_origins(self) -> None:
        self.assertEqual(self.validate(self.provenance), (1, 1))

    def test_observed_source_must_be_registered_licensed_and_network_fetched(
        self,
    ) -> None:
        provenance = copy.deepcopy(self.provenance)
        provenance["sources"][0]["authority"] = "unregistered"  # type: ignore[index]
        with self.assertRaisesRegex(
            authorizer.CompositeAuthorizationError,
            "unregistered authority",
        ):
            self.validate(provenance)

    def test_verified_derived_and_overlay_only_slice_needs_no_network_source(
        self,
    ) -> None:
        provenance = copy.deepcopy(self.provenance)
        provenance["sources"] = provenance["sources"][1:]  # type: ignore[index]
        provenance["source_count"] = len(provenance["sources"])  # type: ignore[arg-type]
        self.assertEqual(self.validate(provenance, []), (0, 0))

    def test_exact_main_overlay_must_remain_inside_manual_categories(self) -> None:
        provenance = copy.deepcopy(self.provenance)
        overlay = provenance["sources"][2]  # type: ignore[index]
        overlay["requested_refs"] = ["../escape.txt"]
        overlay["resolved_ref"] = "../escape.txt"
        with self.assertRaisesRegex(
            authorizer.CompositeAuthorizationError,
            "exact-main overlay provenance is invalid",
        ):
            self.validate(provenance)


if __name__ == "__main__":
    unittest.main()
