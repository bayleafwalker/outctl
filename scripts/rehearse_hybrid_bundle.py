"""Run a local, raw-free clean-install/conformance/rollback rehearsal.

The rehearsal installs only from one verified hybrid bundle into a disposable
environment, runs deterministic local fixtures, prints metadata-only JSON, and
does not publish, deploy, or mutate any external authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import Any, Final

from check_hybrid_bundle import BundleError, canonical_json, check_bundle

MAX_COMMAND_OUTPUT: Final = 1024 * 1024
COMMAND_TIMEOUT: Final = 120.0


class RehearsalError(RuntimeError):
    """The local bundle rehearsal did not prove one required gate."""


def _kill(process: subprocess.Popen[bytes]) -> None:
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)


def _run_bounded(
    argv: Sequence[str],
    *,
    environment: Mapping[str, str],
    timeout: float = COMMAND_TIMEOUT,
) -> subprocess.CompletedProcess[bytes]:
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            env=dict(environment),
        )
    except OSError as error:
        raise RehearsalError(f"cannot start local rehearsal command: {argv[0]!r}") from error
    assert process.stdout is not None
    assert process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    output = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill(process)
                raise RehearsalError(f"local rehearsal command timed out: {argv[0]!r}")
            events = selector.select(min(remaining, 0.25))
            if not events and process.poll() is not None:
                events = selector.select(0)
            for key, _ in events:
                chunk = os.read(key.fileobj.fileno(), 65_536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target = output[key.data]
                target.extend(chunk)
                if len(target) > MAX_COMMAND_OUTPUT:
                    _kill(process)
                    raise RehearsalError(
                        f"local rehearsal command output exceeded its bound: {argv[0]!r}"
                    )
        try:
            return_code = process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as error:
            _kill(process)
            raise RehearsalError(f"local rehearsal command timed out: {argv[0]!r}") from error
    finally:
        selector.close()
        if process.poll() is None:
            _kill(process)
            process.wait()
        process.stdout.close()
        process.stderr.close()
    return subprocess.CompletedProcess(
        list(argv),
        return_code,
        bytes(output["stdout"]),
        bytes(output["stderr"]),
    )


def _require_success(completed: subprocess.CompletedProcess[bytes], label: str) -> bytes:
    if completed.returncode != 0:
        raise RehearsalError(f"{label} failed with exit {completed.returncode}")
    return completed.stdout


def _run_pinned_native(
    executable: Path,
    expected_digest: str,
    arguments: Sequence[str],
    *,
    timeout: float,
) -> subprocess.CompletedProcess[bytes]:
    """Hash and execute one already-opened Linux native artifact."""
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(executable, flags)
    except OSError as error:
        raise RehearsalError("cannot safely open the pinned native artifact") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o111 == 0:
            raise RehearsalError("pinned native artifact is not a regular executable")
        if metadata.st_mode & 0o022:
            raise RehearsalError("pinned native artifact is group/world writable")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        if digest.hexdigest() != expected_digest:
            raise RehearsalError("pinned native artifact digest drifted")
        os.lseek(descriptor, 0, os.SEEK_SET)
        proc_path = f"/proc/self/fd/{descriptor}"
        try:
            return subprocess.run(
                [proc_path, *arguments],
                check=False,
                capture_output=True,
                timeout=timeout,
                pass_fds=(descriptor,),
                cwd="/",
                env={"LANG": "C.UTF-8", "PATH": os.defpath},
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RehearsalError("pinned native execution failed") from error
    finally:
        os.close(descriptor)


def _json_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RehearsalError(f"{label} did not return valid JSON") from error
    if not isinstance(value, dict):
        raise RehearsalError(f"{label} must return a JSON object")
    return value


def _member(bundle: Path, relative: object, label: str) -> Path:
    if not isinstance(relative, str):
        raise RehearsalError(f"{label} path is malformed")
    # The strict checker has already proven the fixed normalized form. This
    # join is intentionally used only after that check succeeds.
    return bundle.joinpath(*relative.split("/"))


def rehearse(
    bundle: Path,
    host_class: str,
    *,
    python: Path,
    uv: Path,
) -> dict[str, object]:
    manifest = check_bundle(bundle)
    native_values = manifest["native"]
    assert isinstance(native_values, list)
    matching = [item for item in native_values if item["host_class"] == host_class]
    if len(matching) != 1:
        raise RehearsalError("requested host class is not present exactly once")
    native = matching[0]
    dependencies = native["python_dependencies"]
    assert isinstance(dependencies, list) and dependencies
    manifest_raw = (bundle / "manifest.json").read_bytes()
    manifest_digest = hashlib.sha256(manifest_raw).hexdigest()
    native_path = _member(bundle, native["path"], "native")
    native_digest = native["sha256"]
    capabilities_digest = native["capabilities"]["sha256"]
    if not isinstance(native_digest, str) or not isinstance(capabilities_digest, str):
        raise RehearsalError("native digests are malformed")
    wheel = _member(bundle, manifest["python"]["path"], "Python wheel")
    dependency_directory = bundle / "artifacts" / "python-dependencies" / host_class

    with tempfile.TemporaryDirectory(prefix="outctl-w8-rehearsal-") as temporary:
        root = Path(temporary)
        virtualenv = root / ".venv"
        clean_environment = {
            "HOME": str(root / "home"),
            "LANG": "C.UTF-8",
            "PATH": os.defpath,
            "PIP_NO_INDEX": "1",
            "UV_CACHE_DIR": str(root / "uv-cache"),
            "UV_NO_INDEX": "1",
        }
        (root / "home").mkdir(mode=0o700)
        _require_success(
            _run_bounded(
                [str(uv), "venv", "--no-project", "--python", str(python), str(virtualenv)],
                environment=clean_environment,
            ),
            "fresh virtual environment creation",
        )
        installed_python = virtualenv / "bin" / "python"
        _require_success(
            _run_bounded(
                [
                    str(uv),
                    "pip",
                    "install",
                    "--python",
                    str(installed_python),
                    "--no-index",
                    "--find-links",
                    str(dependency_directory),
                    str(wheel),
                ],
                environment=clean_environment,
            ),
            "offline Python installation",
        )
        probe = _json_object(
            _require_success(
                _run_bounded(
                    [
                        str(installed_python),
                        "-c",
                        (
                            "import json,outctl,outctl.control,outctl.native,sys;"
                            "print(json.dumps({'outctl':outctl.__version__,"
                            "'python':f'{sys.version_info.major}.{sys.version_info.minor}'}))"
                        ),
                    ],
                    environment=clean_environment,
                ),
                "installed Python import probe",
            ),
            "installed Python import probe",
        )
        if probe != {"outctl": manifest["python"]["version"], "python": "3.12"}:
            raise RehearsalError("installed Python version/import probe does not match the bundle")

        native_capabilities = _run_pinned_native(
            native_path,
            native_digest,
            ("capabilities", "--json"),
            timeout=15,
        )
        capabilities = _json_object(
            _require_success(native_capabilities, "pinned native capability probe"),
            "pinned native capability probe",
        )
        if hashlib.sha256(canonical_json(capabilities)).hexdigest() != capabilities_digest:
            raise RehearsalError("native capability output does not match the bundle pin")

        differential_code = (
            "import json,sys;"
            "from pathlib import Path;"
            "from outctl.native.differential import compare_capture_engines;"
            "r=compare_capture_engines([sys.executable,'-c',"
            "\"import os;os.write(1,b'alpha\\\\x00omega\\\\n');"
            "os.write(2,b'warn\\\\n')\"],Path(sys.argv[2]),"
            "native_binary=Path(sys.argv[1]),native_sha256='sha256:'+sys.argv[3],"
            "max_bytes=4096);"
            "print(json.dumps({'passed':r.passed,'exact':list(r.exact_mismatches),"
            "'semantic':list(r.semantic_mismatches)}))"
        )
        differential = _json_object(
            _require_success(
                _run_bounded(
                    [
                        str(installed_python),
                        "-c",
                        differential_code,
                        str(native_path),
                        str(root / "differential"),
                        native_digest,
                    ],
                    environment=clean_environment,
                ),
                "installed cross-engine conformance fixture",
            ),
            "installed cross-engine conformance fixture",
        )
        if differential != {"passed": True, "exact": [], "semantic": []}:
            raise RehearsalError("installed cross-engine conformance fixture disagreed")

        invocation_marker = root / "native-invocation-count"
        fixture = (
            f"from pathlib import Path;p=Path({str(invocation_marker)!r});p.open('x').write('one')"
        )
        native_run = _run_pinned_native(
            native_path,
            native_digest,
            (
                "run",
                "--spool-root",
                str(root / "native-shadow-spool"),
                "--workspace-id",
                "w8-local-rehearsal",
                "--presentation-mode",
                "metadata",
                "--",
                str(installed_python),
                "-c",
                fixture,
            ),
            timeout=30,
        )
        native_result = _json_object(
            _require_success(native_run, "native one-execution shadow rehearsal"),
            "native one-execution shadow rehearsal",
        )
        command = native_result.get("command")
        if (
            not isinstance(command, dict)
            or command.get("exit_code") != 0
            or native_result.get("capture_status") != "COMPLETE"
            or invocation_marker.read_text(encoding="utf-8") != "one"
        ):
            raise RehearsalError("native one-execution shadow rehearsal did not complete")

        rollback = _json_object(
            _require_success(
                _run_bounded(
                    [str(virtualenv / "bin" / "outctl"), "rollback-check"],
                    environment={
                        **clean_environment,
                        "OUTCTL_ENABLED": "0",
                        "OUTCTL_MODE": "enforce",
                    },
                ),
                "installed rollback rehearsal",
            ),
            "installed rollback rehearsal",
        )
        if rollback.get("passed") is not True or rollback.get("capture_count") != 0:
            raise RehearsalError("installed rollback rehearsal did not bypass capture")

    release = manifest["release"]
    assert isinstance(release, dict)
    engine = native["engine"]
    assert isinstance(engine, dict)
    return {
        "schema_version": "outctl.hybrid-rehearsal/v1",
        "release": {"id": release["id"], "version": release["version"]},
        "repository_commit": release["repository_commit"],
        "manifest_sha256": f"sha256:{manifest_digest}",
        "host_class": host_class,
        "python": {"version": probe["outctl"], "offline_clean_install": True},
        "native": {
            "engine_id": engine["id"],
            "engine_version": engine["version"],
            "artifact_sha256": f"sha256:{native_digest}",
            "capabilities_sha256": f"sha256:{capabilities_digest}",
            "one_execution_shadow": True,
        },
        "conformance": {"exact": True, "semantic": True},
        "rollback": {"bypass": True, "capture_count": 0, "state_migration": False},
        "classification": "metadata-only-local-rehearsal",
        "deployment_or_publication": False,
        "passed": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--host-class", required=True)
    parser.add_argument("--python", required=True, type=Path, help="exact Python 3.12 executable")
    parser.add_argument("--uv", type=Path, default=Path(shutil.which("uv") or "uv"))
    arguments = parser.parse_args()
    try:
        result = rehearse(
            arguments.bundle,
            arguments.host_class,
            python=arguments.python,
            uv=arguments.uv,
        )
    except (BundleError, RehearsalError) as error:
        parser.error(str(error))
    print(canonical_json(result).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
