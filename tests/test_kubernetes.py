from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from outctl.adapter import AdapterIdentity, AdapterMode
from outctl.kubernetes import (
    KubernetesIdentity,
    KubernetesReadError,
    build_kubernetes_receipt,
    run_kubernetes_read,
    validate_kubectl_read_args,
)


def _identity(tmp_path: Path) -> KubernetesIdentity:
    executable = tmp_path / "kubectl"
    executable.write_text(
        "#!/bin/sh\nprintf '%s\\n' \"$@\"\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    kubeconfig = tmp_path / "readonly.kubeconfig"
    kubeconfig.write_text("readonly\n", encoding="utf-8")
    return KubernetesIdentity(
        executable=executable,
        kubeconfig=kubeconfig,
        context="readonly",
        api_server_sha256=hashlib.sha256(b"https://cluster.invalid").hexdigest(),
    )


@pytest.mark.parametrize(
    "args",
    (
        ("delete", "pod", "example"),
        ("get", "secrets", "-A"),
        ("--context", "other", "get", "pods"),
        ("get", "pods", "--", "sh"),
        ("cluster-info", "dump"),
        ("exec", "pod/example", "--", "id"),
    ),
)
def test_structural_read_boundary_rejects_identity_mutation_and_secrets(
    args: tuple[str, ...],
) -> None:
    with pytest.raises(KubernetesReadError):
        validate_kubectl_read_args(args)


def test_identity_binding_is_stable_and_changes_with_logical_argv(tmp_path: Path) -> None:
    identity = _identity(tmp_path)
    argv_a, receipt_a = build_kubernetes_receipt("pods", identity, ("get", "pods", "-A"))
    argv_b, receipt_b = build_kubernetes_receipt("pods-copy", identity, ("get", "pods", "-A"))
    _, receipt_c = build_kubernetes_receipt("nodes", identity, ("get", "nodes"))

    assert argv_a == argv_b
    assert receipt_a.identity_binding_sha256 == receipt_b.identity_binding_sha256
    assert receipt_a.identity_binding_sha256 != receipt_c.identity_binding_sha256
    assert receipt_a.identity_source == "runner_injected"
    assert receipt_a.direct_argv is True
    assert str(identity.kubeconfig) in argv_a
    schema = json.loads(
        (Path(__file__).parents[1] / "schemas/kubernetes-execution-receipt.schema.json").read_text()
    )
    Draft202012Validator(schema).validate(receipt_a.to_dict())


def test_bypass_and_enforce_share_identity_binding_and_direct_argv(tmp_path: Path) -> None:
    identity = _identity(tmp_path)
    common = {
        "logical_command_id": "pods",
        "args": ("get", "pods", "-A"),
        "cluster_identity": identity,
        "adapter_identity": AdapterIdentity(host_id="test", harness="typed-test"),
        "policy_ref": "test",
        "policy_digest": "sha256:" + "0" * 64,
    }
    baseline = asyncio.run(run_kubernetes_read(mode=AdapterMode.BYPASS, **common))
    treatment = asyncio.run(
        run_kubernetes_read(
            mode=AdapterMode.ENFORCE,
            spool_root=tmp_path / "spool",
            **common,
        )
    )

    assert baseline.receipt.identity_binding_sha256 == treatment.receipt.identity_binding_sha256
    assert baseline.execution.command.exit_code == treatment.execution.command.exit_code == 0
    assert treatment.execution.envelope is not None
    invocation = treatment.execution.envelope.invocation
    assert invocation.shell is False
    assert json.dumps(treatment.receipt.to_dict()).find("readonly.kubeconfig") == -1
