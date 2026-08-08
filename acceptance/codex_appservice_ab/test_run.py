from __future__ import annotations

import json
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

import run
from jsonschema import Draft202012Validator
from kubectl_guard import classify_kubectl
from kubectl_readonly_guard import classify_kubectl as classify_readonly_kubectl


class GuardTests(unittest.TestCase):
    def test_classifies_direct_and_wrapped(self) -> None:
        direct = classify_kubectl(
            "direnv exec /projects/dev/appservice kubectl get deployment,pod -A -o wide"
        )
        self.assertEqual(len(direct), 1)
        self.assertFalse(direct[0].wrapped_by_outctl)
        self.assertTrue(direct[0].read_only)

        wrapped = classify_kubectl(
            "uv run --project /projects/dev/outctl outctl run --mode enforce "
            "--spool-root /tmp/x --policy-ref health --policy-digest sha256:"
            + "0" * 64
            + " -- kubectl get pods -A"
        )
        self.assertEqual(len(wrapped), 1)
        self.assertTrue(wrapped[0].wrapped_by_outctl)
        self.assertTrue(wrapped[0].read_only)

        fake_wrapper = classify_kubectl("outctl inspect run -- kubectl get pods -A")
        self.assertEqual(len(fake_wrapper), 1)
        self.assertFalse(fake_wrapper[0].wrapped_by_outctl)

    def test_denies_mutation_and_secret_read(self) -> None:
        delete = classify_kubectl("kubectl delete pod example")
        self.assertFalse(delete[0].read_only)
        secret = classify_kubectl('bash -lc "kubectl get secrets -A"')
        self.assertFalse(secret[0].read_only)

    def test_global_flags_before_verb(self) -> None:
        for classifier in (classify_kubectl, classify_readonly_kubectl):
            value = classifier("kubectl --context appservice -o wide get pods -A")
            self.assertEqual(value[0].verb, "get")
            self.assertEqual(value[0].resource, "pods")
            self.assertTrue(value[0].read_only)

    def test_baseline_guard_contains_no_treatment_guidance(self) -> None:
        guard = Path(run.__file__).with_name("kubectl_readonly_guard.py")
        self.assertNotIn("outctl", guard.read_text(encoding="utf-8").casefold())


class UsageTests(unittest.TestCase):
    def test_exact_terra_cost(self) -> None:
        usage = run.Usage(
            input_tokens=100_000,
            cached_input_tokens=40_000,
            cache_write_input_tokens=10_000,
            output_tokens=10_000,
            reasoning_output_tokens=5_000,
            turn_completed_events=1,
        )
        costs = run._cost_ranges(usage, model="gpt-5.6-terra")
        self.assertTrue(costs["codex_credits"]["exact"])
        # 50k read * 50 + 40k cached * 5 + 10k output * 300 = 5.7 credits.
        self.assertAlmostEqual(costs["codex_credits"]["value"], 5.7)
        # $0.10 read + $0.008 cached + $0.025 cache write + $0.12 output.
        self.assertAlmostEqual(costs["api_equivalent_usd"]["value"], 0.253)

    def test_missing_cache_write_yields_range(self) -> None:
        usage = run.Usage(
            input_tokens=1000,
            cached_input_tokens=500,
            cache_write_input_tokens=None,
            output_tokens=100,
            reasoning_output_tokens=0,
            turn_completed_events=1,
        )
        costs = run._cost_ranges(usage, model="gpt-5.6-terra")
        self.assertFalse(costs["codex_credits"]["exact"])
        self.assertLess(costs["codex_credits"]["minimum"], costs["codex_credits"]["maximum"])


class HarnessValidationTests(unittest.TestCase):
    def test_generated_codex_home_disables_unrelated_context_features(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            worktree = root / "worktree"
            worktree.mkdir()
            run._write_codex_home(
                home,
                worktree=worktree,
                canonical=worktree,
                outctl_project=worktree,
                write_roots=(root / "spool", root / "hook-log"),
                kubernetes_api_host="192.0.2.10",
                auth_source=None,
                reasoning_effort="high",
            )
            config = (home / "config.toml").read_text(encoding="utf-8")
            self.assertIn('web_search = "disabled"', config)
            self.assertIn("hooks = true", config)
            self.assertIn("memories = false", config)
            self.assertIn("external_agent_memory_import = false", config)
            self.assertIn("multi_agent = false", config)
            self.assertIn("multi_agent_v2 = false", config)
            self.assertIn("apps = false", config)
            self.assertIn("plugins = false", config)
            self.assertIn('default_permissions = "outctl-ab-readonly"', config)
            self.assertIn('extends = ":read-only"', config)
            self.assertIn('"192.0.2.10" = "allow"', config)
            self.assertNotIn("sandbox_mode", config)

    def test_codex_command_uses_permission_profile_not_sandbox_flag(self) -> None:
        command = run._build_codex_command(
            codex_bin="codex",
            model="gpt-5.6-terra",
            worktree=Path("/tmp/worktree"),
            schema=Path("/tmp/schema.json"),
            final_path=Path("/tmp/final.json"),
            prompt="test",
        )
        self.assertNotIn("--sandbox", command)
        self.assertIn("--ephemeral", command)

    def test_home_hook_registration_uses_isolated_active_config_layer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worktree = root / "worktree"
            hook_dir = worktree / ".codex" / "hooks"
            hook_dir.mkdir(parents=True)
            (hook_dir / "kubectl_outctl_guard.py").write_text("# guard\n", encoding="utf-8")
            (worktree / ".codex" / "outctl-routing-policy.json").write_text(
                "{}\n", encoding="utf-8"
            )
            home = root / "home"
            home.mkdir()
            run._install_home_hook(home, worktree, arm="A")
            self.assertTrue((home / "hooks" / "kubectl_outctl_guard.py").is_file())
            self.assertTrue((home / "outctl-routing-policy.json").is_file())
            self.assertIn("kubectl_outctl_guard.py", (home / "hooks.json").read_text())

    def test_full_schema_validation_catches_constraint_violation(self) -> None:
        schema = json.loads(
            Path(run.__file__).with_name("health-result.schema.json").read_text(encoding="utf-8")
        )
        validator = Draft202012Validator(schema)
        with tempfile.TemporaryDirectory() as temporary:
            final = Path(temporary) / "final.json"
            final.write_text(
                json.dumps(
                    {
                        "overall_status": "healthy",
                        "summary": "x" * 1801,
                        "coverage": {
                            "cluster_api": {"status": "healthy", "evidence": "ok"},
                            "nodes": {"status": "healthy", "evidence": "ok"},
                            "workloads": {"status": "healthy", "evidence": "ok"},
                            "gitops": {"status": "healthy", "evidence": "ok"},
                            "storage": {"status": "healthy", "evidence": "ok"},
                            "events": {"status": "healthy", "evidence": "ok"},
                        },
                        "checks": [],
                        "findings": [],
                        "limitations": [],
                        "mutations_performed": False,
                    }
                ),
                encoding="utf-8",
            )
            metrics, _, warnings = run._final_metrics(final, validator)
            self.assertTrue(metrics["schema_valid_basic"])
            self.assertFalse(metrics["schema_valid"])
            self.assertTrue(any("schema validation failed" in item for item in warnings))

    def test_model_reroute_disables_pricing(self) -> None:
        schema = json.loads(
            Path(run.__file__).with_name("health-result.schema.json").read_text(encoding="utf-8")
        )
        validator = Draft202012Validator(schema)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            events = root / "events.jsonl"
            stderr = root / "stderr.log"
            final = root / "final.json"
            hooks = root / "hooks.jsonl"
            events.write_text(
                "\n".join(
                    [
                        json.dumps({"type": "thread.started", "thread_id": "t"}),
                        json.dumps(
                            {
                                "type": "error",
                                "message": "fallback model selected after reroute",
                            }
                        ),
                        json.dumps(
                            {
                                "type": "turn.completed",
                                "usage": {
                                    "input_tokens": 1000,
                                    "cached_input_tokens": 500,
                                    "cache_write_input_tokens": 0,
                                    "output_tokens": 100,
                                    "reasoning_output_tokens": 20,
                                },
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            stderr.write_text("", encoding="utf-8")
            hooks.write_text(
                json.dumps({"model": "gpt-5.6-terra", "denied": False}) + "\n",
                encoding="utf-8",
            )
            final.write_text(
                json.dumps(
                    {
                        "overall_status": "healthy",
                        "summary": "healthy",
                        "coverage": {
                            name: {"status": "healthy", "evidence": "ok"}
                            for name in run.REQUIRED_COVERAGE_AREAS
                        },
                        "checks": [],
                        "findings": [],
                        "limitations": [],
                        "mutations_performed": False,
                    }
                ),
                encoding="utf-8",
            )
            result = run.ProcessResult(
                arm="A",
                return_code=0,
                timed_out=False,
                duration_ms=1,
                launched_monotonic_ns=1,
                events_path=events,
                stderr_path=stderr,
                final_path=final,
                hook_log_path=hooks,
                outctl_spool_root=None,
            )
            parsed, _ = run._parse_arm(
                result,
                requested_model="gpt-5.6-terra",
                validator=validator,
            )
            self.assertTrue(parsed["model_reroute_signal"])
            self.assertFalse(parsed["pricing"]["available"])


class EndToEndTests(unittest.TestCase):
    def test_concurrent_pair_with_fake_codex(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "appservice"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "config",
                    "user.email",
                    "test@example.invalid",
                ],
                check=True,
            )
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
            (repo / "AGENTS.md").write_text("# Baseline appservice guidance\n", encoding="utf-8")
            (repo / ".agents" / "skills" / "cluster-health").mkdir(parents=True)
            (repo / ".agents" / "skills" / "cluster-health" / "SKILL.md").write_text(
                "---\nname: cluster-health\ndescription: health\n---\n", encoding="utf-8"
            )
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "baseline"], check=True)

            fake_home = root / "base-codex"
            fake_home.mkdir()
            (fake_home / "auth.json").write_text("{}\n", encoding="utf-8")
            fake_codex = root / "codex"
            fake_codex.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import json, os, pathlib, sys
                    if "--version" in sys.argv:
                        print("codex-cli fake-1")
                        raise SystemExit(0)
                    arm = os.environ["CODEX_AB_ARM"]
                    hook_log = pathlib.Path(os.environ["CODEX_AB_HOOK_LOG"])
                    hook_log.parent.mkdir(parents=True, exist_ok=True)
                    hook_log.write_text(
                        json.dumps({"model": "gpt-5.6-terra", "denied": False})
                        + "\\n"
                    )
                    out = pathlib.Path(sys.argv[sys.argv.index("--output-last-message") + 1])
                    out.parent.mkdir(parents=True, exist_ok=True)
                    result = {
                        "overall_status": "healthy",
                        "summary": "healthy",
                        "coverage": {
                            "cluster_api": {"status": "healthy", "evidence": "ok"},
                            "nodes": {"status": "healthy", "evidence": "ok"},
                            "workloads": {"status": "healthy", "evidence": "ok"},
                            "gitops": {"status": "healthy", "evidence": "ok"},
                            "storage": {"status": "healthy", "evidence": "ok"},
                            "events": {"status": "healthy", "evidence": "ok"},
                        },
                        "checks": [{"area": "cluster", "status": "healthy", "evidence": "ok"}],
                        "findings": [],
                        "limitations": [],
                        "mutations_performed": False,
                    }
                    out.write_text(json.dumps(result))
                    print(json.dumps({"type": "thread.started", "thread_id": "thread-" + arm}))
                    if arm == "A":
                        command = (
                            "outctl run --mode enforce --spool-root /tmp/x "
                            "--policy-ref p --policy-digest sha256:"
                            + "0" * 64
                            + " -- kubectl get pods -A"
                        )
                        output = "x" * 100
                        usage = {
                            "input_tokens": 1000,
                            "cached_input_tokens": 400,
                            "cache_write_input_tokens": 100,
                            "output_tokens": 100,
                            "reasoning_output_tokens": 20,
                        }
                        spool = pathlib.Path(os.environ["OUTCTL_AB_SPOOL_ROOT"])
                        capture = spool / "captures" / "capture-1"
                        capture.mkdir(parents=True, exist_ok=True)
                        (capture / "manifest.json").write_text(json.dumps({
                            "capture_status": "COMPLETE",
                            "streams": {
                                "stdout": {"bytes": 1000},
                                "stderr": {"bytes": 0}
                            }
                        }))
                        (spool / "retrieval-events.jsonl").write_text(
                            json.dumps({"capture_id": "capture-1", "operation": "tail"}) + "\\n"
                        )
                    else:
                        command = "kubectl get pods -A"
                        output = "x" * 1000
                        usage = {
                            "input_tokens": 2000,
                            "cached_input_tokens": 400,
                            "cache_write_input_tokens": 100,
                            "output_tokens": 150,
                            "reasoning_output_tokens": 30,
                        }
                    print(
                        json.dumps(
                            {
                                "type": "item.completed",
                                "item": {
                                    "id": "c1",
                                    "type": "command_execution",
                                    "command": command,
                                    "aggregated_output": output,
                                    "exit_code": 0,
                                    "status": "completed",
                                },
                            }
                        )
                    )
                    print(json.dumps({"type": "turn.completed", "usage": usage}))
                    """
                ),
                encoding="utf-8",
            )
            fake_codex.chmod(0o755)
            fake_kubectl = root / "kubectl"
            fake_kubectl.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env python3
                    import sys
                    args = sys.argv[1:]
                    if "current-context" in args:
                        print("readonly")
                    elif "jsonpath={.clusters[0].cluster.server}" in args:
                        print("https://192.0.2.10:6443")
                    elif args[-4:-2] == ["auth", "can-i"] or "can-i" in args:
                        blocked = any(value in args for value in (
                            "create", "delete", "secrets", "pods/exec",
                            "pods/portforward", "pods/ephemeralcontainers",
                        ))
                        print("no" if blocked else "yes")
                    else:
                        raise SystemExit(2)
                    """
                ),
                encoding="utf-8",
            )
            fake_kubectl.chmod(0o755)
            kubeconfig = root / "read-only.kubeconfig"
            kubeconfig.write_text("apiVersion: v1\nkind: Config\n", encoding="utf-8")
            output = root / "result"
            env = os.environ.copy()
            env["CODEX_HOME"] = str(fake_home)
            completed = subprocess.run(
                [
                    str(Path(run.__file__).resolve()),
                    "--appservice",
                    str(repo),
                    "--canonical-appservice",
                    str(repo),
                    "--kubeconfig",
                    str(kubeconfig),
                    "--context",
                    "readonly",
                    "--kubectl-bin",
                    str(fake_kubectl),
                    "--output",
                    str(output),
                    "--codex-bin",
                    str(fake_codex),
                    "--policy-ref",
                    "health",
                    "--policy-digest",
                    "sha256:" + "0" * 64,
                    "--pairs",
                    "1",
                ],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads((output / "report.json").read_text(encoding="utf-8"))
            planned = json.loads((output / "planned-commands.json").read_text(encoding="utf-8"))
            self.assertIn("--dangerously-bypass-hook-trust", planned[0]["A"])
            self.assertIn("--ephemeral", planned[0]["B"])
            self.assertNotIn("--sandbox", planned[0]["A"])
            pair = report["pairs"][0]
            self.assertIn("pair_valid", pair["comparison"])
            self.assertIn("flags", pair["comparison"])
            self.assertNotIn("valid", pair["comparison"])
            self.assertNotIn("validity_flags", pair["comparison"])
            self.assertTrue(pair["comparison"]["treatment_compliant"])
            self.assertTrue(pair["comparison"]["treatment_capture_accounted"])
            self.assertTrue(pair["comparison"]["pair_valid"])
            self.assertTrue(pair["arms"]["A"]["final"]["schema_valid"])
            self.assertEqual(pair["arms"]["A"]["outctl_spool"]["retained_total_bytes"], 1000)
            self.assertEqual(pair["arms"]["A"]["usage"]["input_tokens"], 1000)
            self.assertEqual(pair["comparison"]["metrics"]["input_tokens"]["reduction_pct"], 50.0)
            self.assertGreater(
                report["experiment"]["model_guidance_inventory"]["delta_bytes_a_minus_b"],
                0,
            )
            self.assertEqual(
                (output / "private" / "pair-001" / "A" / "events.jsonl").stat().st_mode & 0o777,
                0o600,
            )
            self.assertFalse((output / "private" / "pair-001" / "codex-home-A").exists())
            self.assertEqual(report["experiment"]["preflight"]["required_permissions_verified"], 5)
            self.assertEqual(report["experiment"]["preflight"]["prohibited_permissions_denied"], 6)


if __name__ == "__main__":
    unittest.main()
