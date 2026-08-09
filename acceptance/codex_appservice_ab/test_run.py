from __future__ import annotations

import json
import os
import subprocess
import tempfile
import textwrap
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import build_analyst_bundle
import kubectl_guard as treatment_guard
import kubectl_readonly_guard as baseline_guard
import outctl_kubectl_router
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

        routed = classify_kubectl(
            "python3 /opt/outctl_kubectl_router.py run --spool-root /tmp/x -- kubectl get pods -A"
        )
        self.assertEqual(len(routed), 1)
        self.assertTrue(routed[0].wrapped_by_outctl)

        helper = classify_kubectl("outctl-health kubectl get pods -A")
        self.assertEqual(len(helper), 1)
        self.assertTrue(helper[0].wrapped_by_outctl)

    def test_denies_mutation_and_secret_read(self) -> None:
        delete = classify_kubectl("kubectl delete pod example")
        self.assertFalse(delete[0].read_only)
        secret = classify_kubectl('bash -lc "kubectl get secrets -A"')
        self.assertFalse(secret[0].read_only)

    def test_discovery_reference_is_not_misclassified_as_execution(self) -> None:
        for classifier in (classify_kubectl, classify_readonly_kubectl):
            self.assertEqual(classifier("command -v kubectl"), [])
            self.assertEqual(classifier("which kubectl"), [])

    def test_identity_override_and_absolute_escape_are_detected(self) -> None:
        for guard in (treatment_guard, baseline_guard):
            self.assertIsNotNone(
                guard._identity_denial("kubectl --context other get pods", "/pin/kubectl")
            )
            self.assertIsNotNone(
                guard._identity_denial("/usr/bin/kubectl get pods", "/pin/kubectl")
            )
            self.assertIsNone(guard._identity_denial("kubectl get pods", "/pin/kubectl"))

        self.assertIsNotNone(
            baseline_guard._identity_denial(
                "direnv exec . kubectl get pods -A", "/pin/kubectl"
            )
        )

    def test_global_flags_before_verb(self) -> None:
        for classifier in (classify_kubectl, classify_readonly_kubectl):
            value = classifier("kubectl --context appservice -o wide get pods -A")
            self.assertEqual(value[0].verb, "get")
            self.assertEqual(value[0].resource, "pods")
            self.assertTrue(value[0].read_only)

    def test_baseline_guard_contains_no_treatment_guidance(self) -> None:
        guard = Path(run.__file__).with_name("kubectl_readonly_guard.py")
        self.assertNotIn("outctl", guard.read_text(encoding="utf-8").casefold())

    def test_pinned_identity_guidance_is_treatment_neutral(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            worktree = Path(temporary)
            (worktree / "AGENTS.md").write_text("# baseline\n", encoding="utf-8")
            run._append_pinned_identity_guidance(worktree)
            guidance = (worktree / "AGENTS.md").read_text(encoding="utf-8")
            self.assertIn("dedicated read-only credential", guidance)
            self.assertIn("Do not prefix it with `direnv`", guidance)
            self.assertNotIn("outctl", guidance.casefold())

    def test_router_search_uses_only_bounded_projected_windows(self) -> None:
        payload = {
            "capture_id": "capture-1",
            "matches": [
                {"projection": {"text": "first bounded window\n"}},
                {"projection": {"text": "second bounded window\n"}},
            ],
        }
        capture_id, text = outctl_kubectl_router._safe_search(json.dumps(payload).encode())
        self.assertEqual(capture_id, "capture-1")
        self.assertIn("first bounded window", text)
        self.assertIn("second bounded window", text)

    def test_router_search_redacts_exact_value_before_model_output(self) -> None:
        secret = "fixture-search-secret"
        payload = {
            "capture_id": "capture-1",
            "matches": [{"projection": {"text": f"marker secret={secret}\n"}}],
        }
        _, text = outctl_kubectl_router._safe_search(
            json.dumps(payload).encode(), exact_redactions=(secret,)
        )
        self.assertIn("marker", text)
        self.assertNotIn(secret, text)
        self.assertIn("[REDACTED]", text)

    def test_router_rewrites_logical_kubectl_to_pinned_direct_argv(self) -> None:
        prefix = ["/usr/bin/kubectl", "--kubeconfig", "/scoped", "--context", "scoped"]
        with mock.patch.object(outctl_kubectl_router, "_run", return_value=0) as execute:
            result = outctl_kubectl_router.main(
                [
                    "run",
                    "--outctl-command-json",
                    json.dumps(["/opt/outctl"]),
                    "--kubectl-command-json",
                    json.dumps(prefix),
                    "--spool-root",
                    "/spool",
                    "--policy-ref",
                    "health",
                    "--policy-digest",
                    "sha256:" + "0" * 64,
                    "--",
                    "kubectl",
                    "get",
                    "pods",
                ]
            )
            self.assertEqual(result, 0)
        routed = execute.call_args.args[0]
        separator = routed.index("--")
        self.assertEqual(routed[separator + 1 :], [*prefix, "get", "pods"])


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
    def test_controlled_completion_detects_missing_corpus_command(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            events = Path(raw) / "events.jsonl"
            rows = [{"type": "thread.started", "thread_id": "thread-1"}]
            for index in range(5):
                rows.append({
                    "type": "item.completed",
                    "item": {
                        "type": "command_execution",
                        "status": "completed",
                        "command": f"kubectl get pods -A -o wide # {index}",
                        "aggregated_output": "ok",
                    },
                })
            events.write_text("".join(json.dumps(row) + "\n" for row in rows))
            self.assertTrue(run._controlled_completion_needed(events, arm="B"))
            self.assertEqual(run._thread_id(events), "thread-1")

    def test_controlled_codex_command_is_resumable(self) -> None:
        command = run._build_codex_command(
            codex_bin="codex",
            model="model",
            worktree=Path("/tmp/worktree"),
            schema=Path("/tmp/schema.json"),
            final_path=Path("/tmp/final.json"),
            prompt="prompt",
            ephemeral=False,
        )
        self.assertNotIn("--ephemeral", command)

    def test_analyst_bundle_is_deterministic_and_excludes_bytecode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "acceptance/codex_appservice_ab/__pycache__").mkdir(parents=True)
            (root / "acceptance/codex_appservice_ab/run.py").write_text("pass\n")
            (root / "acceptance/codex_appservice_ab/__pycache__/run.pyc").write_bytes(b"bytecode")
            first, second = root / "first.zip", root / "second.zip"
            inputs = [Path("acceptance/codex_appservice_ab")]
            build_analyst_bundle.build(root, first, "analyst-safe", inputs)
            build_analyst_bundle.build(root, second, "analyst-safe", inputs)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                self.assertNotIn(
                    "acceptance/codex_appservice_ab/__pycache__/run.pyc",
                    archive.namelist(),
                )
                manifest = json.loads(archive.read("bundle-manifest.json"))
            self.assertEqual(manifest["package_class"], "analyst-safe")
            self.assertEqual(len(manifest["files"]), 1)

    @staticmethod
    def _identity(value: str = "same") -> dict[str, object]:
        return {"identity_sha256": value, "matches_launcher_preflight": True}

    def test_opt_in_guidance_is_brief_and_direct_reads_remain_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            worktree = Path(temporary)
            (worktree / "AGENTS.md").write_text("# baseline\n", encoding="utf-8")
            run._append_arm_a_guidance(
                worktree,
                "long router prefix",
                "long retrieval prefix",
                treatment_mode="opt-in",
            )
            skill = (worktree / ".agents/skills/outctl-kubectl-health/SKILL.md").read_text(
                encoding="utf-8"
            )
            self.assertIn("outctl-health kubectl", skill)
            self.assertIn("Direct read-only `kubectl` is fine", skill)
            self.assertNotIn("exactly one", skill)
            self.assertLess(len(skill.encode("utf-8")), 1200)

    def test_router_bounds_batched_search_results(self) -> None:
        payload = {
            "capture_id": "capture-1",
            "queries": [
                {
                    "pattern": "FailedMount",
                    "matches": [
                        {"projection": {"text": "FailedMount evidence"}}
                    ],
                },
                {"pattern": "CrashLoopBackOff", "matches": []},
            ],
        }
        capture_id, text = outctl_kubectl_router._safe_search_many(
            json.dumps(payload).encode()
        )
        self.assertEqual(capture_id, "capture-1")
        self.assertIn("FailedMount evidence", text)
        self.assertIn("no bounded matches", text)

    def test_opt_in_comparison_records_adoption_without_mandating_it(self) -> None:
        arm = {
            "exit_code": 0,
            "timed_out": False,
            "final": {"schema_valid": True, "overall_status": "healthy"},
            "model_observed": True,
            "model_mismatch": False,
            "model_reroute_signal": False,
            "commands": {"kubectl_completed": 1, "kubectl_direct_completed": 1},
            "hooks": {"events": 1, "read_only_policy_denials": 0},
            "outctl_spool": {},
            "cluster_identity": self._identity(),
        }
        comparison = run._compare_pair(arm, arm, set(), set(), 0, treatment_mode="opt-in")
        self.assertFalse(comparison["treatment_adopted"])
        self.assertFalse(comparison["treatment_compliant"])
        self.assertTrue(comparison["pair_valid"])

    def test_failed_opt_in_attempt_invalidates_pair(self) -> None:
        arm = {
            "exit_code": 0,
            "timed_out": False,
            "final": {"schema_valid": True, "overall_status": "healthy"},
            "model_observed": True,
            "model_mismatch": False,
            "model_reroute_signal": False,
            "commands": {
                "kubectl_via_outctl_attempts": 1,
                "kubectl_via_outctl_completed": 0,
                "retrieval_tool_turns": 0,
            },
            "hooks": {"events": 1, "read_only_policy_denials": 0},
            "outctl_spool": {},
            "cluster_identity": self._identity(),
        }
        baseline = {
            **arm,
            "commands": {"kubectl_completed": 1, "kubectl_direct_completed": 1},
        }
        comparison = run._compare_pair(arm, baseline, set(), set(), 0, treatment_mode="opt-in")
        self.assertEqual(comparison["treatment_adoption_state"], "attempted_failure")
        self.assertFalse(comparison["treatment_capture_accounted"])
        self.assertFalse(comparison["pair_valid"])

    def test_opt_in_quality_disagreement_remains_an_outcome(self) -> None:
        arm = {
            "exit_code": 0,
            "timed_out": False,
            "final": {"schema_valid": True, "overall_status": "degraded"},
            "model_observed": True,
            "model_mismatch": False,
            "model_reroute_signal": False,
            "commands": {"kubectl_completed": 1, "kubectl_direct_completed": 1},
            "hooks": {"events": 1, "read_only_policy_denials": 0},
            "outctl_spool": {},
            "cluster_identity": self._identity(),
        }
        comparison = run._compare_pair(
            arm,
            arm,
            {("finding:A", "high")},
            {("finding:B", "high")},
            0,
            treatment_mode="opt-in",
        )
        self.assertFalse(comparison["quality_oracle_passed"])
        self.assertTrue(comparison["pair_valid"])
        self.assertTrue(comparison["validity"]["protocol_valid"])
        self.assertFalse(comparison["outcomes"]["quality_noninferior"])
        self.assertTrue(comparison["economics"]["eligible_for_analysis"])
        self.assertIn(
            "arms disagreed on critical/high finding identifiers or classifications",
            comparison["flags"],
        )

    def test_frozen_expected_facts_score_quality_without_excluding_pair(self) -> None:
        arm = {
            "exit_code": 0,
            "timed_out": False,
            "final": {"schema_valid": True, "overall_status": "degraded"},
            "model_observed": True,
            "model_mismatch": False,
            "model_reroute_signal": False,
            "commands": {"kubectl_completed": 1, "kubectl_direct_completed": 1},
            "hooks": {"events": 1, "read_only_policy_denials": 0},
            "outctl_spool": {},
            "cluster_identity": self._identity(),
        }
        expected = {("coverage:nodes", "degraded"), ("finding:node", "high")}
        comparison = run._compare_pair(
            arm,
            arm,
            {("coverage:nodes", "degraded")},
            expected,
            0,
            treatment_mode="opt-in",
            expected_signature=expected,
            expected_critical={("finding:node", "high")},
        )
        self.assertEqual(comparison["outcomes"]["quality_score_a"], 0.5)
        self.assertEqual(comparison["outcomes"]["quality_score_b"], 1.0)
        self.assertTrue(comparison["outcomes"]["critical_miss_a"])
        self.assertFalse(comparison["outcomes"]["quality_noninferior"])
        self.assertTrue(comparison["validity"]["protocol_valid"])

    def test_identity_mismatch_invalidates_pair_before_metrics(self) -> None:
        arm = {
            "exit_code": 0,
            "timed_out": False,
            "final": {"schema_valid": True, "overall_status": "healthy"},
            "model_observed": True,
            "model_mismatch": False,
            "model_reroute_signal": False,
            "commands": {"kubectl_completed": 1, "kubectl_direct_completed": 1},
            "hooks": {"events": 1, "read_only_policy_denials": 0},
            "outctl_spool": {},
            "cluster_identity": self._identity("A"),
        }
        other = {**arm, "cluster_identity": self._identity("B")}
        comparison = run._compare_pair(arm, other, set(), set(), 0, treatment_mode="opt-in")
        self.assertFalse(comparison["cluster_identity_match"])
        self.assertFalse(comparison["pair_valid"])
        self.assertEqual(comparison["metrics"], {})

    def test_shell_pin_survives_login_and_rejects_identity_override_in_guard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real-kubectl"
            real.write_text("#!/bin/sh\nprintf '%s\\n' \"$*\"\n", encoding="utf-8")
            real.chmod(0o755)
            shell_env = run._install_isolated_shell_home(
                root / "shell-home",
                kubectl_bin=real,
                kubeconfig=root / "scoped.kubeconfig",
                context="scoped",
                pinned_path=os.environ.get("PATH", ""),
            )
            completed = subprocess.run(
                ["bash", "-lc", "kubectl get pods"],
                env={
                    **os.environ,
                    "HOME": str(root / "shell-home"),
                    "BASH_ENV": str(shell_env),
                },
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0)
            self.assertIn("--kubeconfig", completed.stdout)
            self.assertIn("--context scoped", completed.stdout)
            self.assertIsNotNone(
                baseline_guard._identity_denial("kubectl --context other get pods", str(real))
            )

    def test_quality_signature_canonicalizes_model_ids_and_pod_suffixes(self) -> None:
        schema = json.loads(
            Path(run.__file__).with_name("health-result.schema.json").read_text(encoding="utf-8")
        )
        validator = Draft202012Validator(schema)

        def result(finding_id: str, component: str) -> dict[str, object]:
            return {
                "overall_status": "degraded",
                "summary": "degraded",
                "coverage": {
                    name: {"status": "healthy", "evidence": "ok"}
                    for name in run.REQUIRED_COVERAGE_AREAS
                },
                "checks": [],
                "findings": [
                    {
                        "id": finding_id,
                        "severity": "high",
                        "component": component,
                        "summary": "one affected workload",
                        "evidence": [],
                    }
                ],
                "limitations": [],
                "mutations_performed": False,
            }

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            left = root / "left.json"
            right = root / "right.json"
            left.write_text(
                json.dumps(result("HIGH-WORKLOAD", "vscode/actionq-schema-v8-h7p7k")),
                encoding="utf-8",
            )
            right.write_text(
                json.dumps(result("APP-H-001", "vscode/actionq-schema-v8")),
                encoding="utf-8",
            )
            _, left_signature, _ = run._final_metrics(left, validator)
            _, right_signature, _ = run._final_metrics(right, validator)

        self.assertEqual(left_signature, right_signature)

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
        spool = Path("/tmp/outctl-spool")
        command = run._build_codex_command(
            codex_bin="codex",
            model="gpt-5.6-terra",
            worktree=Path("/tmp/worktree"),
            schema=Path("/tmp/schema.json"),
            final_path=Path("/tmp/final.json"),
            prompt="test",
            additional_write_dirs=(spool,),
        )
        self.assertNotIn("--sandbox", command)
        self.assertIn("--ephemeral", command)
        self.assertEqual(command[command.index("--add-dir") + 1], str(spool))

    def test_commissioning_failure_stops_later_pairs(self) -> None:
        self.assertTrue(
            run._commissioning_failed(
                {
                    "commands": {
                        "kubectl_via_outctl_attempts": 1,
                        "kubectl_via_outctl_completed": 0,
                    },
                    "outctl_spool": {"capture_directory_count": 0},
                }
            )
        )

    def test_router_prefix_uses_only_spool_local_uv_state(self) -> None:
        executable, common = run._router_prefixes(
            kubeconfig=Path("/tmp/readonly.kubeconfig"),
            router=Path("/opt/outctl-router.py"),
            launcher=("uv", "run", "--project", "/opt/outctl", "outctl"),
        )
        self.assertIn("UV_OFFLINE=1", executable)
        self.assertIn('UV_CACHE_DIR="$OUTCTL_AB_SPOOL_ROOT/uv-cache"', executable)
        self.assertIn('TMPDIR="$OUTCTL_AB_SPOOL_ROOT/tmp"', executable)
        self.assertIn("KUBECONFIG=/tmp/readonly.kubeconfig", executable)
        self.assertIn("--outctl-command-json", common)
        self.assertIn('"uv","run","--project","/opt/outctl","outctl"', common)
        self.assertFalse(
            run._commissioning_failed(
                {
                    "commands": {
                        "kubectl_via_outctl_attempts": 1,
                        "kubectl_via_outctl_completed": 1,
                    },
                    "outctl_spool": {"capture_directory_count": 1},
                }
            )
        )

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
                        "checks": [{
                            "area": "cluster",
                            "status": "healthy",
                            "evidence": "ok",
                            "evidence_refs": [{
                                "capture_id": "capture-1",
                                "operation": "projection",
                                "stream": None,
                                "start": None,
                                "end": None,
                            }],
                        }],
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
                    "--treatment-mode",
                    "opt-in",
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
