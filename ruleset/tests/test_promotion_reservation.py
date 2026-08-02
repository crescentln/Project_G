from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import textwrap
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ruleset-update.yml"
REPOSITORY = "crescentln/Project_G"
SOURCE_SHA = "a" * 40
SELECTED_RUN_ID = "101"
EXPECTED_FINGERPRINT = "d" * 64


def extract_step_script(step_name: str) -> str:
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    start = next(
        index for index, line in enumerate(lines) if f"- name: {step_name}" in line
    )
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


def run_payload(run_id: int, conclusion: str) -> dict:
    return {
        "id": run_id,
        "status": "completed",
        "conclusion": conclusion,
        "head_branch": "main",
        "head_sha": SOURCE_SHA,
        "head_repository": {"full_name": REPOSITORY},
        "path": ".github/workflows/source-discovery.yml",
        "event": "schedule",
        "created_at": "2026-08-01T12:00:00Z",
    }


class PromotionReservationBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = extract_step_script(
            "Verify candidate identity and source freshness"
        )

    def execute(
        self, newer: dict, *, newer_artifact_name: str = ""
    ) -> tuple[subprocess.CompletedProcess[str], str, str]:
        selected = run_payload(int(SELECTED_RUN_ID), "success")
        endpoints: dict[str, object] = {
            f"repos/{REPOSITORY}/actions/runs/{SELECTED_RUN_ID}": selected,
            (
                f"repos/{REPOSITORY}/actions/workflows/source-discovery.yml/"
                "runs?branch=main&per_page=100"
            ): {"workflow_runs": [newer, selected]},
        }
        if newer_artifact_name:
            endpoints[
                f"repos/{REPOSITORY}/actions/runs/{newer['id']}/artifacts?per_page=100"
            ] = {
                "artifacts": [
                    {
                        "id": 9001,
                        "name": newer_artifact_name,
                        "expired": False,
                    }
                ]
            }
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = pathlib.Path(raw_temp)
            fake_bin = temp / "bin"
            fake_bin.mkdir()
            fake_gh = fake_bin / "gh"
            fake_gh.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import json
                    import os
                    import sys

                    args = sys.argv[1:]
                    if len(args) < 2 or args[0] != "api":
                        raise SystemExit(f"unsupported gh invocation: {args}")
                    endpoints = json.loads(os.environ["FAKE_GH_ENDPOINTS"])
                    endpoint = args[1]
                    if endpoint not in endpoints:
                        raise SystemExit(f"missing fake endpoint: {endpoint}")
                    print(json.dumps(endpoints[endpoint]))
                    """
                ),
                encoding="utf-8",
            )
            fake_gh.chmod(0o755)
            fake_date = fake_bin / "date"
            fake_date.write_text(
                "#!/bin/sh\n"
                "case \"$*\" in *-d*) echo 1000 ;; *) echo 1100 ;; esac\n",
                encoding="utf-8",
            )
            fake_date.chmod(0o755)
            output_path = temp / "github-output.txt"
            summary_path = temp / "summary.md"
            env = os.environ.copy()
            env.update(
                {
                    "PATH": f"{fake_bin}:{env['PATH']}",
                    "FAKE_GH_ENDPOINTS": json.dumps(endpoints),
                    "GITHUB_OUTPUT": str(output_path),
                    "GITHUB_STEP_SUMMARY": str(summary_path),
                    "RUNNER_TEMP": str(temp),
                    "REPOSITORY": REPOSITORY,
                    "CANDIDATE_RUN_ID": SELECTED_RUN_ID,
                    "EXPECTED_SOURCE_SHA": SOURCE_SHA,
                    "EXPECTED_DECISION_FINGERPRINT": EXPECTED_FINGERPRINT,
                    "CANDIDATE_ARTIFACT_NAME": (
                        f"ruleset-candidate-low-{'b' * 64}-"
                        f"{EXPECTED_FINGERPRINT}-{'e' * 64}"
                    ),
                    "PROMOTION_MODE": "auto-low-risk",
                }
            )
            result = subprocess.run(
                ["/bin/bash", "-c", self.script],
                cwd=temp,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            output = output_path.read_text() if output_path.exists() else ""
            summary = summary_path.read_text() if summary_path.exists() else ""
            return result, output, summary

    def test_newer_failed_discovery_closes_without_false_failure(self) -> None:
        result, output, summary = self.execute(run_payload(102, "failure"))
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertTrue(output.rstrip().endswith("continue=false"), output)
        self.assertIn("Publication reservation closed", summary)
        self.assertIn("no user action is required", summary)

    def test_newer_changed_decision_freezes_reserved_candidate(self) -> None:
        changed_artifact = (
            f"ruleset-candidate-low-{'b' * 64}-{'f' * 64}-{'e' * 64}"
        )
        result, output, summary = self.execute(
            run_payload(102, "success"),
            newer_artifact_name=changed_artifact,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertTrue(output.rstrip().endswith("continue=false"), output)
        self.assertIn("changed the automated decision", summary)


if __name__ == "__main__":
    unittest.main()
