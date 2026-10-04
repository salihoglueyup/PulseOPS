"""Release plumbing that only runs at release time, checked on every commit."""
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent


def test_package_contents_exist():
    spec = yaml.safe_load((ROOT / "packaging" / "nfpm.yaml").read_text())
    for item in spec["contents"]:
        src = item["src"]
        if src.startswith(("dist/", "/")):  # the built binary and the symlink target
            continue
        assert (ROOT / src).exists(), f"nfpm.yaml ships a missing file: {src}"


def test_release_workflow_paths_exist():
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    for path in set(re.findall(r"(packaging/[\w.]+|pulseops/[\w/]+\.(?:py|tcss))", workflow)):
        assert (ROOT / path).exists(), f"release.yml references a missing file: {path}"
