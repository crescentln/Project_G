from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import subprocess
import tempfile
import textwrap
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "freshness-watchdog.yml"
REPOSITORY = "crescentln/Project_G"
MAIN_SHA = "a" * 40


def extract_evidence_python() -> str:
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    step = next(
        index
        for index, line in enumerate(lines)
        if "- name: Select exact discovery and release evidence" in line
    )
    start = next(
        index for index in range(step, len(lines)) if "python3 - <<'PY'" in lines[index]
    )
    indent = len(lines[start]) - len(lines[start].lstrip())
    body: list[str] = []
    for line in lines[start + 1 :]:
        if line.strip() == "PY" and len(line) - len(line.lstrip()) == indent:
            break
        body.append(line[indent:] if line.strip() else "")
    else:
        raise AssertionError("Watchdog evidence heredoc is unterminated")
    return "\n".join(body) + "\n"


def timestamp(minutes_ago: int) -> str:
    value = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=minutes_ago)
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def discovery_run(
    run_id: int,
    *,
    status: str,
    conclusion: str | None,
    minutes_ago: int,
) -> dict:
    return {
        "id": run_id,
        "status": status,
        "conclusion": conclusion,
        "head_branch": "main",
        "head_sha": MAIN_SHA,
        "head_repository": {"full_name": REPOSITORY},
        "path": ".github/workflows/source-discovery.yml",
        "event": "schedule",
        "created_at": timestamp(minutes_ago),
        "updated_at": timestamp(max(minutes_ago - 1, 0)),
    }


class FreshnessWatchdogBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = extract_evidence_python()

    def execute(
        self, runs: list[dict]
    ) -> tuple[subprocess.CompletedProcess[str], str, str]:
        gate_run_id = 5001
        endpoints = {
            f"repos/{REPOSITORY}/commits/main": {
                "sha": MAIN_SHA,
                "commit": {"committer": {"date": timestamp(2)}},
            },
            f"repos/{REPOSITORY}/contents/README.md?ref=main": {
                "size": 0,
                "sha": "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
            },
            f"repos/{REPOSITORY}/commits/{MAIN_SHA}/status": {
                "statuses": [
                    {
                        "id": 1,
                        "context": "ruleset/gate",
                        "state": "success",
                        "updated_at": timestamp(1),
                        "avatar_url": "https://avatars.githubusercontent.com/in/15368?v=4",
                        "target_url": (
                            f"https://github.com/{REPOSITORY}/actions/runs/"
                            f"{gate_run_id}"
                        ),
                    }
                ]
            },
            f"repos/{REPOSITORY}/actions/runs/{gate_run_id}": {
                "id": gate_run_id,
                "status": "completed",
                "conclusion": "success",
                "path": ".github/workflows/main-gate.yml",
                "repository": {"full_name": REPOSITORY},
            },
            (
                f"repos/{REPOSITORY}/actions/workflows/source-discovery.yml/"
                "runs?branch=main&per_page=100"
            ): {"workflow_runs": runs},
        }
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = pathlib.Path(raw_temp)
            (temp / ".watchdog").mkdir()
            (temp / ".watchdog" / "advisories.txt").write_text("")
            (temp / ".watchdog" / "failures.txt").write_text("")
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
            output_path = temp / "github-output.txt"
            env = os.environ.copy()
            env.update(
                {
                    "PATH": f"{fake_bin}:{env['PATH']}",
                    "FAKE_GH_ENDPOINTS": json.dumps(endpoints),
                    "GITHUB_OUTPUT": str(output_path),
                    "REPOSITORY": REPOSITORY,
                    "VERIFIER_SHA": MAIN_SHA,
                }
            )
            result = subprocess.run(
                ["python3", "-c", self.script],
                cwd=temp,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            output = output_path.read_text() if output_path.exists() else ""
            advisories = (temp / ".watchdog" / "advisories.txt").read_text()
            return result, output, advisories

    def test_latest_completed_failure_is_not_masked_by_older_success(self) -> None:
        latest_failure = discovery_run(
            102, status="completed", conclusion="failure", minutes_ago=4
        )
        older_success = discovery_run(
            101, status="completed", conclusion="success", minutes_ago=10
        )
        result, output, advisories = self.execute(
            [older_success, latest_failure]
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "latest completed Source Discovery did not succeed: run=102",
            result.stderr + result.stdout,
        )
        self.assertEqual(output, "")
        self.assertEqual(advisories, "")

    def test_newer_active_retry_is_automatic_convergence_attention(self) -> None:
        active_retry = discovery_run(
            103, status="in_progress", conclusion=None, minutes_ago=1
        )
        failed = discovery_run(
            102, status="completed", conclusion="failure", minutes_ago=4
        )
        result, output, advisories = self.execute([failed, active_retry])
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("convergence_pending=true", output)
        self.assertIn("still running automatically", advisories)

    def test_newer_active_run_masks_no_successful_candidate_state(self) -> None:
        active = discovery_run(
            103, status="queued", conclusion=None, minutes_ago=1
        )
        success = discovery_run(
            102, status="completed", conclusion="success", minutes_ago=4
        )
        result, output, advisories = self.execute([success, active])
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("convergence_pending=true", output)
        self.assertIn("still running automatically", advisories)


if __name__ == "__main__":
    unittest.main()
