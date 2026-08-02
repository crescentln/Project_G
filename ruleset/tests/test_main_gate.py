from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import textwrap
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "main-gate.yml"
REPOSITORY = "crescentln/Project_G"
HEAD_SHA = "a" * 40


def extract_gate_script() -> str:
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    start = next(index for index, line in enumerate(lines) if "python3 - <<'PY'" in line)
    indent = len(lines[start]) - len(lines[start].lstrip())
    body: list[str] = []
    for line in lines[start + 1 :]:
        if line.strip() == "PY" and len(line) - len(line.lstrip()) == indent:
            break
        body.append(line[indent:] if line.strip() else "")
    else:
        raise AssertionError("Main Gate Python heredoc is unterminated")
    return "\n".join(body) + "\n"


def check_run(name: str, app_id: int, *, conclusion: str = "success") -> dict:
    return {
        "id": len(name) * 100 + app_id,
        "name": name,
        "app": {"id": app_id},
        "status": "completed",
        "conclusion": conclusion,
        "started_at": "2026-08-01T12:00:00Z",
    }


class MainGateBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = extract_gate_script()

    def execute(
        self,
        trigger: str,
        *,
        missing_analysis: str = "",
        failed_check: str = "",
    ) -> tuple[subprocess.CompletedProcess[str], list[list[str]]]:
        actions = [
            check_run("repository-governance", 15368),
            check_run("full-validation", 15368),
            check_run("gitleaks", 15368),
            check_run("Analyze Python", 15368),
        ]
        if trigger == "pull_request":
            actions.extend(
                [
                    check_run("dependency-review", 15368),
                    check_run("CodeQL", 57789),
                    check_run("gitleaks", 57789),
                ]
            )
        if failed_check:
            for row in actions:
                if row["name"] == failed_check:
                    row["conclusion"] = "failure"

        analyses = [
            {
                "id": 1,
                "commit_sha": HEAD_SHA,
                "ref": "refs/heads/main",
                "tool": {"name": "CodeQL"},
                "category": "/language:python",
                "created_at": "2026-08-01T12:01:00Z",
                "error": "",
                "warning": "",
                "results_count": 0,
            },
            {
                "id": 2,
                "commit_sha": HEAD_SHA,
                "ref": "refs/heads/main",
                "tool": {"name": "Gitleaks"},
                "category": ".github/workflows/secret-scan.yml:gitleaks",
                "created_at": "2026-08-01T12:01:00Z",
                "error": "",
                "warning": "",
                "results_count": 0,
            },
        ]
        if missing_analysis:
            analyses = [
                row for row in analyses if row["tool"]["name"] != missing_analysis
            ]

        event = {
            "workflow_run": {
                "head_sha": HEAD_SHA,
                "head_branch": "main" if trigger == "push" else "feature",
                "head_repository": {"full_name": REPOSITORY},
                "event": trigger,
            }
        }
        pulls = [
            {
                "state": "open",
                "base": {"ref": "main", "repo": {"full_name": REPOSITORY}},
                "head": {"sha": HEAD_SHA},
            }
        ]
        endpoints = {
            f"repos/{REPOSITORY}/commits/{HEAD_SHA}/pulls": pulls,
            f"repos/{REPOSITORY}/commits/main": {"sha": HEAD_SHA},
            (
                f"repos/{REPOSITORY}/commits/{HEAD_SHA}/"
                "check-runs?filter=latest&per_page=100"
            ): {"check_runs": actions},
            (
                f"repos/{REPOSITORY}/code-scanning/analyses?"
                "ref=refs/heads/main&per_page=100"
            ): analyses,
            f"repos/{REPOSITORY}/contents/README.md?ref={HEAD_SHA}": {
                "size": 0,
                "sha": "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
            },
        }

        with tempfile.TemporaryDirectory() as raw_temp:
            temp = pathlib.Path(raw_temp)
            fake_bin = temp / "bin"
            fake_bin.mkdir()
            event_path = temp / "event.json"
            event_path.write_text(json.dumps(event), encoding="utf-8")
            log_path = temp / "gh-posts.jsonl"
            fake_gh = fake_bin / "gh"
            fake_gh.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import json
                    import os
                    import pathlib
                    import sys

                    args = sys.argv[1:]
                    if not args or args[0] != "api":
                        raise SystemExit(f"unsupported gh invocation: {args}")
                    if "--method" in args:
                        with pathlib.Path(os.environ["FAKE_GH_LOG"]).open("a", encoding="utf-8") as handle:
                            handle.write(json.dumps(args) + "\\n")
                        print("{}")
                        raise SystemExit(0)
                    endpoint = args[1]
                    endpoints = json.loads(os.environ["FAKE_GH_ENDPOINTS"])
                    if endpoint not in endpoints:
                        raise SystemExit(f"missing fake endpoint: {endpoint}")
                    print(json.dumps(endpoints[endpoint]))
                    """
                ),
                encoding="utf-8",
            )
            fake_gh.chmod(0o755)
            script_path = temp / "main_gate.py"
            script_path.write_text(self.script, encoding="utf-8")
            env = os.environ.copy()
            env.update(
                {
                    "PATH": f"{fake_bin}:{env['PATH']}",
                    "FAKE_GH_ENDPOINTS": json.dumps(endpoints),
                    "FAKE_GH_LOG": str(log_path),
                    "GATE_MAX_ATTEMPTS": "1",
                    "GATE_POLL_SECONDS": "0",
                    "GITHUB_EVENT_PATH": str(event_path),
                    "GITHUB_RUN_ID": "12345",
                    "GITHUB_SERVER_URL": "https://github.com",
                    "REPOSITORY": REPOSITORY,
                }
            )
            result = subprocess.run(
                ["python3", str(script_path)],
                cwd=REPO_ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            posts = (
                [json.loads(line) for line in log_path.read_text().splitlines()]
                if log_path.exists()
                else []
            )
            return result, posts

    @staticmethod
    def assert_status(posts: list[list[str]], expected: str) -> None:
        assert len(posts) == 1, posts
        assert f"state={expected}" in posts[0], posts
        assert "context=ruleset/gate" in posts[0], posts

    def test_push_uses_exact_code_scanning_analyses_without_app_checks(self) -> None:
        result, posts = self.execute("push")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assert_status(posts, "success")

    def test_pull_request_uses_advanced_security_check_runs(self) -> None:
        result, posts = self.execute("pull_request")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assert_status(posts, "success")

    def test_missing_push_analysis_remains_pending_without_false_red_run(self) -> None:
        result, posts = self.execute("push", missing_analysis="Gitleaks")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assert_status(posts, "pending")
        self.assertIn("remains fail-closed", result.stdout)

    def test_failed_required_check_rejects_the_sha(self) -> None:
        result, posts = self.execute("push", failed_check="full-validation")
        self.assertNotEqual(result.returncode, 0)
        self.assert_status(posts, "failure")


if __name__ == "__main__":
    unittest.main()
