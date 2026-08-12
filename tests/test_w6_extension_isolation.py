from __future__ import annotations

import os
from pathlib import Path

import pytest
from test_w6_extension_support import install_test_distribution

from outctl.extensions import (
    ExtensionContext,
    ExtensionInvocation,
    ExtensionPhase,
    ExtensionRequest,
    ExtensionSandboxUnavailable,
    ExtensionStatus,
    discover_extensions,
    invoke_extension,
)
from outctl.extensions.contracts import ExtensionKind, ExtensionResult
from outctl.extensions.protocol import result_document

DIGEST = "sha256:" + "b" * 64


def _invocation(site: Path, input_value: dict[str, object], deadline_ms: int = 2_000):
    discovered = discover_extensions([site])
    return ExtensionInvocation(
        discovered[0].pin,
        ExtensionRequest(
            discovered[0].pin.extension_id,
            ExtensionContext(
                "workspace-1",
                "session-1",
                None,
                deadline_ms,
                ExtensionPhase.COMMISSIONING,
                DIGEST,
            ),
            input_value,
            4_096,
        ),
    )


def test_real_sandbox_hides_host_and_irreversibly_denies_process_and_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace_probe = tmp_path / "workspace-private"
    spool_probe = tmp_path / "spool-private"
    workspace_probe.write_text("host-private", encoding="utf-8")
    spool_probe.write_text("raw-capture", encoding="utf-8")
    monkeypatch.setenv("OUTCTL_EXTENSION_TEST_SECRET", "must-not-cross")
    source = r"""
import os
import socket
import subprocess
from outctl.extensions.contracts import ExtensionKind, ExtensionResult

def _blocked(call):
    try:
        call()
    except OSError as exc:
        return exc.errno == 1
    return False

def extension(request):
    checks = {
        "socket": _blocked(lambda: socket.socket()),
        "socketpair": _blocked(lambda: socket.socketpair()),
        "fork": _blocked(lambda: os.fork()),
        "exec": _blocked(lambda: os.execve("/does-not-exist", ["x"], {})),
        "subprocess": _blocked(lambda: subprocess.run(["/does-not-exist"])),
    }
    for index, path in enumerate(request.input["probe_paths"]):
        try:
            open(path, "rb")
        except OSError:
            checks[f"host_hidden_{index}"] = True
        else:
            checks[f"host_hidden_{index}"] = False
    checks["secret_absent"] = "OUTCTL_EXTENSION_TEST_SECRET" not in os.environ
    return ExtensionResult.accepted(request, ExtensionKind.FACTS, {"facts": checks})
"""
    site = install_test_distribution(tmp_path / "plugin", source=source)
    invocation = _invocation(site, {"probe_paths": [str(workspace_probe), str(spool_probe)]})
    result = invoke_extension(invocation, plugin_roots=(site,))
    assert result.status is ExtensionStatus.ACCEPTED
    assert all(result.payload["facts"].values())


def test_deadline_kills_worker_and_output_floods_are_bounded(tmp_path: Path) -> None:
    hanging = install_test_distribution(
        tmp_path / "hang",
        source="def extension(request):\n    while True:\n        pass\n",
    )
    timed_out = invoke_extension(_invocation(hanging, {}, deadline_ms=250), plugin_roots=(hanging,))
    assert timed_out.status is ExtensionStatus.TIMED_OUT
    assert timed_out.diagnostics == ("extension-deadline",)

    flooding = install_test_distribution(
        tmp_path / "flood",
        source=(
            "import os\n"
            "from outctl.extensions.contracts import ExtensionKind, ExtensionResult\n"
            "def extension(request):\n"
            "    os.write(1, b'x' * 8192)\n"
            "    return ExtensionResult.accepted(request, ExtensionKind.FACTS, "
            "{'facts': {'ok': True}})\n"
        ),
    )
    flooded = invoke_extension(_invocation(flooding, {}), plugin_roots=(flooding,))
    assert flooded.status is ExtensionStatus.MALFORMED
    assert flooded.diagnostics == ("extension-output-overflow",)

    stderr_flooding = install_test_distribution(
        tmp_path / "stderr-flood",
        distribution="stderr-flood-extension",
        module="stderr_flood_extension",
        source=(
            "import os\n"
            "from outctl.extensions.contracts import ExtensionKind, ExtensionResult\n"
            "def extension(request):\n"
            "    os.write(2, b'y' * 8192)\n"
            "    return ExtensionResult.accepted(request, ExtensionKind.FACTS, "
            "{'facts': {'ok': True}})\n"
        ),
    )
    stderr_flooded = invoke_extension(
        _invocation(stderr_flooding, {}), plugin_roots=(stderr_flooding,)
    )
    assert stderr_flooded.status is ExtensionStatus.MALFORMED
    assert stderr_flooded.diagnostics == ("extension-output-overflow",)


def test_exact_result_limit_is_accepted_and_limit_plus_one_is_malformed(
    tmp_path: Path,
) -> None:
    source = (
        "from outctl.extensions.contracts import ExtensionKind, ExtensionResult\n"
        "def extension(request):\n"
        "    return ExtensionResult.accepted(request, ExtensionKind.FACTS, "
        "{'facts': {'text': 'x' * request.input['size']}})\n"
    )
    site = install_test_distribution(tmp_path / "plugin", source=source)
    baseline = _invocation(site, {"size": 0})
    baseline_result = ExtensionResult.accepted(
        baseline.request, ExtensionKind.FACTS, {"facts": {"text": ""}}
    )
    fill = baseline.request.max_result_bytes - len(result_document(baseline, baseline_result))
    exact = _invocation(site, {"size": fill})
    assert (
        len(
            result_document(
                exact,
                ExtensionResult.accepted(
                    exact.request,
                    ExtensionKind.FACTS,
                    {"facts": {"text": "x" * fill}},
                ),
            )
        )
        == exact.request.max_result_bytes
    )
    accepted = invoke_extension(exact, plugin_roots=(site,))
    assert accepted.status is ExtensionStatus.ACCEPTED

    over = invoke_extension(_invocation(site, {"size": fill + 1}), plugin_roots=(site,))
    assert over.status is ExtensionStatus.MALFORMED


def test_missing_or_untrusted_bwrap_never_falls_back_in_process(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    site = install_test_distribution(
        tmp_path / "plugin",
        source=(
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('unsafe')\n"
            "def extension(request):\n    return None\n"
        ),
    )
    with pytest.raises(ExtensionSandboxUnavailable):
        invoke_extension(
            _invocation(site, {}),
            plugin_roots=(site,),
            bwrap_path=tmp_path / "missing-bwrap",
        )
    assert not marker.exists()


def test_untrusted_nix_runtime_environment_is_not_forwarded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "must-not-exist"
    site = install_test_distribution(
        tmp_path / "plugin",
        source=(
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('unsafe')\n"
            "def extension(request):\n    return None\n"
        ),
    )
    fake_loader = tmp_path / "attacker-loader"
    fake_loader.write_bytes(b"not-a-loader")
    fake_loader.chmod(0o755)
    monkeypatch.setenv("NIX_LD", str(fake_loader))
    monkeypatch.delenv("NIX_LD_LIBRARY_PATH", raising=False)
    with pytest.raises(ExtensionSandboxUnavailable, match="Nix extension runtime"):
        invoke_extension(_invocation(site, {}), plugin_roots=(site,))
    assert not marker.exists()


def test_plugin_root_must_be_an_installed_distribution_not_repo_or_spool(
    tmp_path: Path,
) -> None:
    site = install_test_distribution(tmp_path / "plugin", source="def extension(request): pass\n")
    invocation = _invocation(site, {})
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    spool = tmp_path / "spool" / "site"
    spool.mkdir(parents=True)
    for unsafe in (Path("/"), repo, spool):
        with pytest.raises(ExtensionSandboxUnavailable):
            invoke_extension(invocation, plugin_roots=(unsafe,))


def test_sandbox_closes_unlisted_inherited_file_descriptors(tmp_path: Path) -> None:
    source = r"""
import os
from outctl.extensions.contracts import ExtensionKind, ExtensionResult
def extension(request):
    try:
        os.fstat(request.input["fd"])
    except OSError:
        closed = True
    else:
        closed = False
    return ExtensionResult.accepted(request, ExtensionKind.FACTS, {"facts": {"closed": closed}})
"""
    site = install_test_distribution(tmp_path / "plugin", source=source)
    descriptor = os.open(tmp_path / "outside", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        result = invoke_extension(_invocation(site, {"fd": descriptor}), plugin_roots=(site,))
    finally:
        os.close(descriptor)
    assert result.status is ExtensionStatus.ACCEPTED
    assert result.payload == {"facts": {"closed": True}}
