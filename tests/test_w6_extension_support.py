from __future__ import annotations

import csv
import shutil
from pathlib import Path


def install_test_distribution(
    root: Path,
    *,
    distribution: str = "outctl-test-extension",
    version: str = "1.0.0",
    extension_id: str = "test-extension",
    module: str = "test_extension",
    source: str,
) -> Path:
    site = root / "site"
    package = site / module
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(source, encoding="utf-8")
    dist_info = site / f"{distribution.replace('-', '_')}-{version}.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        f"Metadata-Version: 2.4\nName: {distribution}\nVersion: {version}\n",
        encoding="utf-8",
    )
    (dist_info / "entry_points.txt").write_text(
        f"[outctl.extensions.v1]\n{extension_id} = {module}:extension\n",
        encoding="utf-8",
    )
    members = [
        f"{module}/__init__.py",
        f"{dist_info.name}/METADATA",
        f"{dist_info.name}/entry_points.txt",
        f"{dist_info.name}/RECORD",
    ]
    with (dist_info / "RECORD").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        for member in members:
            writer.writerow((member, "", ""))
    return site


def install_example_distribution(root: Path, example: Path) -> Path:
    if example.name == "kubernetes":
        distribution = "outctl-example-kubernetes-extension"
        extension_id = "kubernetes"
        module = "outctl_example_kubernetes"
    elif example.name == "custom":
        distribution = "outctl-example-custom-extension"
        extension_id = "custom-summary"
        module = "outctl_example_custom"
    else:
        raise ValueError("unknown example")
    source = (example / "src" / module / "__init__.py").read_text(encoding="utf-8")
    return install_test_distribution(
        root,
        distribution=distribution,
        extension_id=extension_id,
        module=module,
        source=source,
    )


def copy_site(source: Path, target: Path) -> Path:
    return Path(shutil.copytree(source, target / "site"))
