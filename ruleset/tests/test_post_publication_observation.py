from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import textwrap
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "post-publication-observation.yml"
REPOSITORY = "crescentln/Project_G"
OBSERVATION_SHA = "a" * 40
PROMOTION_RUN_ID = "7001"
OBSERVER_RUN_ID = "8001"
ARTIFACT_NAME = f"ruleset-candidate-none-{'b' * 64}-{'c' * 64}-{'d' * 64}"


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


def observation_id() -> str:
    payload = (
        PROMOTION_RUN_ID.encode()
        + b"\0"
        + OBSERVATION_SHA.encode()
        + b"\0"
        + OBSERVER_RUN_ID.encode()
    )
    return hashlib.sha256(payload).hexdigest()


class PostPublicationObservationBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = extract_step_script("Dispatch and select exact live observation")

    def execute(
        self, *, first_conclusion: str = "success", main_sha: str = OBSERVATION_SHA
    ) -> tuple[subprocess.CompletedProcess[str], str, list[list[str]]]:
        identifier = observation_id()
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = pathlib.Path(raw_temp)
            fake_bin = temp / "bin"
            fake_bin.mkdir()
            state_path = temp / "state.json"
            state_path.write_text(
                json.dumps(
                    {
                        "dispatch_count": 0,
                        "date_epoch_count": 0,
                        "first_conclusion": first_conclusion,
                        "main_sha": main_sha,
                    }
                ),
                encoding="utf-8",
            )
            dispatch_log = temp / "dispatches.jsonl"
            fake_gh = fake_bin / "gh"
            fake_gh.write_text(
                textwrap.dedent(
                    f"""\
                    #!/usr/bin/env python3
                    import json
                    import os
                    import pathlib
                    import sys

                    state_path = pathlib.Path(os.environ["FAKE_STATE"])
                    state = json.loads(state_path.read_text())
                    args = sys.argv[1:]
                    if args[:2] == ["workflow", "run"]:
                        state["dispatch_count"] += 1
                        state_path.write_text(json.dumps(state))
                        with pathlib.Path(os.environ["FAKE_DISPATCH_LOG"]).open("a") as handle:
                            handle.write(json.dumps(args) + "\\n")
                        raise SystemExit(0)
                    if not args or args[0] != "api":
                        raise SystemExit(f"unsupported gh invocation: {{args}}")
                    endpoint = args[1]
                    if endpoint == "repos/{REPOSITORY}/commits/main":
                        payload = {{"sha": state["main_sha"]}}
                    elif endpoint.endswith("source-discovery.yml/runs?branch=main&per_page=100"):
                        attempt = max(state["dispatch_count"], 1)
                        payload = {{"workflow_runs": [{{
                            "id": 9000 + attempt,
                            "head_sha": "{OBSERVATION_SHA}",
                            "created_at": "2026-08-01T12:00:0%dZ" % attempt,
                            "display_title": "Source Discovery {identifier} attempt-%d" % attempt,
                            "event": "workflow_dispatch",
                            "path": ".github/workflows/source-discovery.yml",
                            "head_repository": {{"full_name": "{REPOSITORY}"}},
                        }}]}}
                    elif endpoint.startswith("repos/{REPOSITORY}/actions/runs/900") and endpoint.endswith("/artifacts?per_page=100"):
                        payload = {{"artifacts": [{{
                            "id": 77,
                            "name": "{ARTIFACT_NAME}",
                            "expired": False,
                        }}]}}
                    elif endpoint.startswith("repos/{REPOSITORY}/actions/runs/900"):
                        attempt = int(endpoint.rsplit("/", 1)[1]) - 9000
                        conclusion = state["first_conclusion"] if attempt == 1 else "success"
                        payload = {{
                            "id": 9000 + attempt,
                            "status": "completed",
                            "conclusion": conclusion,
                            "head_sha": "{OBSERVATION_SHA}",
                            "head_repository": {{"full_name": "{REPOSITORY}"}},
                            "display_title": "Source Discovery {identifier} attempt-%d" % attempt,
                        }}
                    else:
                        raise SystemExit(f"missing fake endpoint: {{endpoint}}")
                    if "--jq" in args:
                        query = args[args.index("--jq") + 1]
                        if query != ".sha":
                            raise SystemExit(f"unsupported --jq: {{query}}")
                        print(payload["sha"])
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
                    import json
                    import os
                    import pathlib
                    import sys

                    state_path = pathlib.Path(os.environ["FAKE_STATE"])
                    state = json.loads(state_path.read_text())
                    if any("%Y-%m-%d" in arg for arg in sys.argv[1:]):
                        print("2026-08-01T12:00:0%dZ" % max(state["dispatch_count"], 1))
                    else:
                        state["date_epoch_count"] += 1
                        state_path.write_text(json.dumps(state))
                        print(1000 + state["date_epoch_count"])
                    """
                ),
                encoding="utf-8",
            )
            fake_date.chmod(0o755)
            fake_sleep = fake_bin / "sleep"
            fake_sleep.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fake_sleep.chmod(0o755)

            output_path = temp / "github-output.txt"
            summary_path = temp / "summary.md"
            env = os.environ.copy()
            env.update(
                {
                    "PATH": f"{fake_bin}:{env['PATH']}",
                    "FAKE_STATE": str(state_path),
                    "FAKE_DISPATCH_LOG": str(dispatch_log),
                    "GITHUB_OUTPUT": str(output_path),
                    "GITHUB_STEP_SUMMARY": str(summary_path),
                    "GITHUB_RUN_ID": OBSERVER_RUN_ID,
                    "OBSERVATION_SHA": OBSERVATION_SHA,
                    "PROMOTION_RUN_ID": PROMOTION_RUN_ID,
                    "REPOSITORY": REPOSITORY,
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
            output = output_path.read_text() if output_path.exists() else ""
            dispatches = (
                [json.loads(line) for line in dispatch_log.read_text().splitlines()]
                if dispatch_log.exists()
                else []
            )
            return result, output, dispatches

    def test_exact_successful_observation_is_correlated(self) -> None:
        result, output, dispatches = self.execute()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("superseded=false", output)
        self.assertIn("run_id=9001", output)
        self.assertIn(f"observation_id={observation_id()}", output)
        self.assertIn("observation_attempt=1", output)
        self.assertEqual(len(dispatches), 1)
        self.assertIn(f"observation_id={observation_id()}", dispatches[0])
        self.assertIn("observation_attempt=1", dispatches[0])

    def test_failed_observation_retries_once_automatically(self) -> None:
        result, output, dispatches = self.execute(first_conclusion="failure")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("run_id=9002", output)
        self.assertIn("observation_attempt=2", output)
        self.assertEqual(len(dispatches), 2)
        self.assertIn("observation_attempt=2", dispatches[1])

    def test_main_advance_closes_as_superseded_without_dispatch(self) -> None:
        result, output, dispatches = self.execute(main_sha="f" * 40)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("superseded=true", output)
        self.assertEqual(dispatches, [])


if __name__ == "__main__":
    unittest.main()
