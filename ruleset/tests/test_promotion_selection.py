from __future__ import annotations

import base64
import io
import json
import os
import pathlib
import re
import subprocess
import tempfile
import textwrap
import unittest
import zipfile


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ruleset-update.yml"
REPOSITORY = "crescentln/Project_G"
SOURCE_SHA = "c" * 40
SEMANTIC_DIGEST = "a" * 64
DECISION_FINGERPRINT = "d" * 64
IDENTITY_DIGEST = "e" * 64
LOW_ARTIFACT = (
    f"ruleset-candidate-low-{SEMANTIC_DIGEST}-"
    f"{DECISION_FINGERPRINT}-{IDENTITY_DIGEST}"
)
HIGH_ARTIFACT = LOW_ARTIFACT.replace("candidate-low-", "candidate-high-")


def extract_step_script(step_name: str) -> str:
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    marker = f"- name: {step_name}"
    start = next(index for index, line in enumerate(lines) if marker in line)
    run_index = next(
        index
        for index in range(start + 1, len(lines))
        if lines[index].lstrip() == "run: |"
    )
    run_indent = len(lines[run_index]) - len(lines[run_index].lstrip())
    block_indent = run_indent + 2
    block: list[str] = []
    for line in lines[run_index + 1 :]:
        if line.strip() and len(line) - len(line.lstrip()) < block_indent:
            break
        block.append(line[block_indent:] if line.strip() else "")
    return "\n".join(block) + "\n"


def run_payload(run_id: int, *, conclusion: str = "success") -> dict[str, object]:
    minute = (run_id - 100) * 10
    return {
        "id": run_id,
        "status": "completed",
        "conclusion": conclusion,
        "head_branch": "main",
        "head_sha": SOURCE_SHA,
        "head_repository": {"full_name": REPOSITORY},
        "path": ".github/workflows/source-discovery.yml",
        "event": "schedule",
        "created_at": f"2026-08-01T12:{minute:02d}:00Z",
    }


def artifact_payload(name: str, artifact_id: int) -> dict[str, object]:
    return {
        "artifacts": [
            {
                "id": artifact_id,
                "name": name,
                "expired": False,
            }
        ]
    }


class PromotionSelectionTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.script = extract_step_script(
            "Select an automatically reviewed stable candidate"
        )

    @staticmethod
    def artifact_zip(name: str) -> bytes:
        match = re.fullmatch(
            r"ruleset-candidate-(low|high)-[0-9a-f]{64}-"
            r"([0-9a-f]{64})-[0-9a-f]{64}",
            name,
        )
        if match is None:
            raise AssertionError(f"invalid test artifact: {name}")
        risk, fingerprint = match.groups()
        review = {
            "schema": "project-g-automated-review-v2",
            "eligible": True,
            "required_stable_cycles": 2,
            "minimum_cycle_separation_seconds": 300,
            "review_policy": "unattended-evidence-gated-v2",
            "changed_categories": ["global"],
            "risk_level": risk,
            "risk_markers": [],
            "policy_modes": ["low-risk" if risk == "low" else "review"],
            "category_evidence": [],
            "source_evidence": [],
            "blockers": [],
        }
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr(
                "automated-review.json",
                json.dumps(review, sort_keys=True, separators=(",", ":")) + "\n",
            )
            archive.writestr("decision-fingerprint.txt", fingerprint + "\n")
            archive.writestr(
                "candidate-identity.json",
                json.dumps({"artifact": name}, sort_keys=True) + "\n",
            )
            archive.writestr(
                "candidate-decision.json",
                json.dumps({"fingerprint": fingerprint}, sort_keys=True) + "\n",
            )
            archive.writestr("source-sha.txt", SOURCE_SHA + "\n")
            archive.writestr("ruleset-dist.tar.gz", b"attested candidate archive")
        return payload.getvalue()

    def fake_data(
        self,
        runs: list[dict[str, object]],
        artifacts: dict[int, dict[str, object]],
    ) -> dict[str, object]:
        data: dict[str, object] = {
            f"repos/{REPOSITORY}/contents/README.md?ref=main": {
                "size": 0,
                "sha": "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
            },
            (
                f"repos/{REPOSITORY}/actions/workflows/source-discovery.yml/"
                "runs?branch=main&per_page=100"
            ): {"workflow_runs": runs},
            f"repos/{REPOSITORY}/commits/main": {"sha": SOURCE_SHA},
        }
        for run in runs:
            run_id = int(run["id"])
            data[f"repos/{REPOSITORY}/actions/runs/{run_id}"] = run
        for run_id, payload in artifacts.items():
            data[
                f"repos/{REPOSITORY}/actions/runs/{run_id}/artifacts?per_page=100"
            ] = payload
            for artifact in payload["artifacts"]:
                artifact_id = int(artifact["id"])
                artifact_name = str(artifact["name"])
                data[
                    f"repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip"
                ] = {
                    "__base64__": base64.b64encode(
                        self.artifact_zip(artifact_name)
                    ).decode("ascii")
                }
        return data

    def execute(
        self,
        *,
        event_name: str,
        runs: list[dict[str, object]],
        artifacts: dict[int, dict[str, object]],
        input_run_id: str = "",
        input_artifact_name: str = "",
        fail_attestation_for: str = "",
        event_run_id: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = pathlib.Path(raw_temp)
            fake_bin = temp / "bin"
            fake_bin.mkdir()
            fake_gh = fake_bin / "gh"
            fake_gh.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import base64
                    import json
                    import os
                    import sys

                    args = sys.argv[1:]
                    if args and args[0] == "attestation" and args[1:2] == ["verify"]:
                        if os.environ.get("FAIL_ATTESTATION_FOR", "") in args[2] and os.environ.get("FAIL_ATTESTATION_FOR"):
                            raise SystemExit("forced attestation verification failure")
                        raise SystemExit(0)
                    if len(args) < 2 or args[0] != "api":
                        raise SystemExit(f"unsupported gh invocation: {args}")
                    endpoint = args[1]
                    data = json.loads(os.environ["FAKE_GH_DATA"])
                    if endpoint not in data:
                        raise SystemExit(f"missing fake endpoint: {endpoint}")
                    payload = data[endpoint]
                    if isinstance(payload, dict) and "__base64__" in payload:
                        sys.stdout.buffer.write(base64.b64decode(payload["__base64__"]))
                        raise SystemExit(0)
                    if "--jq" in args:
                        query = args[args.index("--jq") + 1]
                        if query not in {".size", ".sha"}:
                            raise SystemExit(f"unsupported fake --jq: {query}")
                        print(payload[query[1:]])
                    else:
                        print(json.dumps(payload))
                    """
                ),
                encoding="utf-8",
            )
            fake_gh.chmod(0o755)
            fake_date = fake_bin / "date"
            fake_date.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import datetime as dt
                    import sys

                    args = sys.argv[1:]
                    if "-d" in args:
                        raw = args[args.index("-d") + 1]
                        stamp = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
                        print(int(stamp.timestamp()))
                    else:
                        print(int(dt.datetime(2026, 8, 1, 13, tzinfo=dt.timezone.utc).timestamp()))
                    """
                ),
                encoding="utf-8",
            )
            fake_date.chmod(0o755)

            event_path = temp / "event.json"
            current = next(
                (
                    run
                    for run in runs
                    if event_run_id is not None and int(run["id"]) == event_run_id
                ),
                runs[0],
            )
            event_path.write_text(
                json.dumps(
                    {
                        "workflow_run": {
                            "id": current["id"],
                            "conclusion": current["conclusion"],
                            "head_branch": current["head_branch"],
                        }
                    }
                ),
                encoding="utf-8",
            )
            output_path = temp / "github-output.txt"
            env = os.environ.copy()
            env.update(
                {
                    "PATH": f"{fake_bin}:{env['PATH']}",
                    "FAKE_GH_DATA": json.dumps(self.fake_data(runs, artifacts)),
                    "FAIL_ATTESTATION_FOR": fail_attestation_for,
                    "GITHUB_EVENT_PATH": str(event_path),
                    "GITHUB_OUTPUT": str(output_path),
                    "EVENT_NAME": event_name,
                    "INPUT_RUN_ID": input_run_id,
                    "INPUT_ARTIFACT_NAME": input_artifact_name,
                    "REPOSITORY": REPOSITORY,
                    "RUNNER_TEMP": str(temp),
                }
            )
            result = subprocess.run(
                ["/bin/bash", "-c", self.script],
                cwd=REPO_ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            result.github_output = (
                output_path.read_text(encoding="utf-8")
                if output_path.exists()
                else ""
            )
            return result

    def test_manual_retry_cannot_bypass_latest_or_stability_gates(self) -> None:
        current = run_payload(102)
        previous = run_payload(101)
        result = self.execute(
            event_name="workflow_dispatch",
            runs=[current, previous],
            artifacts={
                102: artifact_payload(LOW_ARTIFACT, 9102),
                101: artifact_payload(LOW_ARTIFACT, 9101),
            },
            input_run_id="102",
            input_artifact_name=LOW_ARTIFACT,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("should_publish=true", result.github_output)
        self.assertIn(
            f"candidate_decision_fingerprint={DECISION_FINGERPRINT}",
            result.github_output,
        )

        newer = run_payload(103)
        newer["status"] = "in_progress"
        newer["conclusion"] = None
        blocked = self.execute(
            event_name="workflow_dispatch",
            runs=[newer, current],
            artifacts={102: artifact_payload(LOW_ARTIFACT, 9102)},
            input_run_id="102",
            input_artifact_name=LOW_ARTIFACT,
        )
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("latest Source Discovery run", blocked.stdout)

    def test_auto_low_risk_requires_adjacent_success_with_same_decision(self) -> None:
        current = run_payload(102)
        previous = run_payload(101)
        result = self.execute(
            event_name="workflow_run",
            runs=[current, previous],
            artifacts={
                102: artifact_payload(LOW_ARTIFACT, 9102),
                101: artifact_payload(LOW_ARTIFACT, 9101),
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("should_publish=true", result.github_output)

    def test_queued_automatic_promotion_closes_cleanly_when_superseded(self) -> None:
        current = run_payload(102)
        newer = run_payload(103)
        newer["status"] = "in_progress"
        newer["conclusion"] = None
        result = self.execute(
            event_name="workflow_run",
            runs=[newer, current],
            artifacts={102: artifact_payload(LOW_ARTIFACT, 9102)},
            event_run_id=102,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertNotIn("should_publish=true", result.github_output)
        self.assertIn("superseded this queued promotion", result.stdout)

    def test_auto_high_risk_uses_the_same_unattended_evidence_gate(self) -> None:
        current = run_payload(102)
        previous = run_payload(101)
        result = self.execute(
            event_name="workflow_run",
            runs=[current, previous],
            artifacts={
                102: artifact_payload(HIGH_ARTIFACT, 9202),
                101: artifact_payload(HIGH_ARTIFACT, 9201),
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("should_publish=true", result.github_output)
        self.assertIn("promotion_mode=auto-high-risk", result.github_output)
        self.assertIn("environment_name=ruleset-production", result.github_output)

    def test_failed_or_changed_adjacent_cycle_resets_stability(self) -> None:
        current = run_payload(102)
        failed = run_payload(101, conclusion="failure")
        failed_result = self.execute(
            event_name="workflow_run",
            runs=[current, failed],
            artifacts={102: artifact_payload(LOW_ARTIFACT, 9102)},
        )
        self.assertEqual(failed_result.returncode, 0)
        self.assertNotIn("should_publish=true", failed_result.github_output)
        self.assertIn("stability reset", failed_result.stdout)

        changed_decision = "1" * 64
        changed_artifact = (
            f"ruleset-candidate-low-{SEMANTIC_DIGEST}-"
            f"{changed_decision}-{'f' * 64}"
        )
        changed_result = self.execute(
            event_name="workflow_run",
            runs=[current, run_payload(101)],
            artifacts={
                102: artifact_payload(LOW_ARTIFACT, 9102),
                101: artifact_payload(changed_artifact, 9101),
            },
        )
        self.assertEqual(changed_result.returncode, 0)
        self.assertNotIn("should_publish=true", changed_result.github_output)
        self.assertIn("full identity were not stable", changed_result.stdout)

        changed_identity = LOW_ARTIFACT[:-64] + "f" * 64
        identity_result = self.execute(
            event_name="workflow_run",
            runs=[current, run_payload(101)],
            artifacts={
                102: artifact_payload(LOW_ARTIFACT, 9102),
                101: artifact_payload(changed_identity, 9101),
            },
        )
        self.assertEqual(identity_result.returncode, 0)
        self.assertNotIn("should_publish=true", identity_result.github_output)
        self.assertIn("full identity were not stable", identity_result.stdout)

    def test_adjacent_cycles_must_be_at_least_300_seconds_apart(self) -> None:
        current = run_payload(102)
        previous = run_payload(101)
        previous["created_at"] = "2026-08-01T12:19:59Z"
        result = self.execute(
            event_name="workflow_run",
            runs=[current, previous],
            artifacts={
                102: artifact_payload(LOW_ARTIFACT, 9102),
                101: artifact_payload(LOW_ARTIFACT, 9101),
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertNotIn("should_publish=true", result.github_output)
        self.assertIn("less than 300 seconds apart", result.stdout)

    def test_either_cycle_attestation_failure_blocks_selection(self) -> None:
        current = run_payload(102)
        previous = run_payload(101)
        artifacts = {
            102: artifact_payload(LOW_ARTIFACT, 9102),
            101: artifact_payload(LOW_ARTIFACT, 9101),
        }
        for target in ("current-ruleset-dist", "previous-ruleset-dist"):
            with self.subTest(target=target):
                result = self.execute(
                    event_name="workflow_run",
                    runs=[current, previous],
                    artifacts=artifacts,
                    fail_attestation_for=target,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("should_publish=true", result.github_output)
                self.assertIn(
                    "forced attestation verification failure",
                    result.stderr + result.stdout,
                )


if __name__ == "__main__":
    unittest.main()
