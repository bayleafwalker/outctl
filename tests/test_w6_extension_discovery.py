from __future__ import annotations

from pathlib import Path

import pytest
from test_w6_extension_support import install_test_distribution

from outctl.extensions.discovery import (
    ExtensionDiscoveryError,
    ExtensionPin,
    discover_extensions,
    select_extension,
)


def test_discovery_is_metadata_only_deterministic_and_exactly_pinned(tmp_path: Path) -> None:
    marker = tmp_path / "imported"
    site = install_test_distribution(
        tmp_path,
        source=(
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('loaded')\n"
            "def extension(request):\n    return None\n"
        ),
    )
    first = discover_extensions([site])
    second = discover_extensions([site])
    assert [item.pin for item in first] == [item.pin for item in second]
    assert not marker.exists(), "metadata discovery imported extension code"
    assert select_extension(first, first[0].pin).pin == first[0].pin

    old_pin = first[0].pin
    (site / "test_extension" / "__init__.py").write_text(
        "def extension(request):\n    return None\n# changed\n", encoding="utf-8"
    )
    changed = discover_extensions([site])
    assert changed[0].pin.fingerprint != old_pin.fingerprint
    with pytest.raises(ExtensionDiscoveryError, match="absent, ambiguous, or changed"):
        select_extension(changed, old_pin)


def test_duplicate_extension_ids_fail_closed_independent_of_enumeration_order(
    tmp_path: Path,
) -> None:
    first = install_test_distribution(
        tmp_path / "a",
        distribution="first-extension",
        extension_id="same-id",
        module="first_extension",
        source="def extension(request):\n    return None\n",
    )
    second = install_test_distribution(
        tmp_path / "b",
        distribution="second-extension",
        extension_id="same-id",
        module="second_extension",
        source="def extension(request):\n    return None\n",
    )
    with pytest.raises(ExtensionDiscoveryError, match="globally unique"):
        discover_extensions([first, second])
    with pytest.raises(ExtensionDiscoveryError, match="globally unique"):
        discover_extensions([second, first])


def test_pin_rejects_unversioned_unsafe_or_unfingerprinted_metadata() -> None:
    digest = "sha256:" + "a" * 64
    with pytest.raises(ExtensionDiscoveryError):
        ExtensionPin("bad id", "package", "1.0", "module:extension", digest)
    with pytest.raises(ExtensionDiscoveryError):
        ExtensionPin("good", "package", "1.0", "module:extension()", digest)
    with pytest.raises(ExtensionDiscoveryError):
        ExtensionPin("good", "package", "1.0", "module:extension", "latest")
