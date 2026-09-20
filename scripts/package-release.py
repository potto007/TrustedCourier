#!/usr/bin/env python3
"""Package an already built release without reading any local deployment state."""
import argparse
import hashlib
import io
import json
import re
import subprocess
import tarfile
from pathlib import Path

VERSION = r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?:[0-9A-Za-z-]+)(?:\.[0-9A-Za-z-]+)*)?"


PLUGIN_FILES = [
    ".claude-plugin/marketplace.json",
    "plugins/claude-trustedcourier/.claude-plugin/plugin.json",
    "plugins/claude-trustedcourier/bin/tc-claude-hook",
    "plugins/claude-trustedcourier/hooks/hooks.json",
    "plugins/claude-trustedcourier/skills/setup/SKILL.md",
    "plugins/claude-trustedcourier/skills/use/SKILL.md",
    "docs/claude-code.md",
    "docs/integrations/codex-cli.md",
    "docs/decisions/0031-fifo-dispatch-and-codex-read-allowlist.md",
]


def release_binaries(platform):
    names = ["tc", "openbao-plugin"]
    if platform.startswith("linux_"):
        names += ["tc-exec", "tc-claude-hook"]
    return names


def validate_version(value):
    if not re.fullmatch(VERSION, value):
        raise ValueError("expected vMAJOR.MINOR.PATCH with optional prerelease suffix")
    if "-" in value:
        for part in value.split("-", 1)[1].split("."):
            if part.isdigit() and len(part) > 1 and part.startswith("0"):
                raise ValueError("numeric prerelease identifiers cannot have leading zeroes")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", type=validate_version)
    parser.add_argument("platform", choices=["linux_amd64", "linux_arm64", "darwin_amd64", "darwin_arm64"])
    parser.add_argument("build_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    src = Path(__file__).resolve().parent.parent
    binaries = release_binaries(args.platform)
    # Verify exactly the expected binaries, not arbitrary paths from a manifest.
    expected = "".join(f"{hashlib.sha256((args.build_dir / name).read_bytes()).hexdigest()}  {name}\n"
                       for name in binaries)
    if (args.build_dir / "SHA256SUMS").read_text() != expected:
        raise ValueError("binary checksum verification failed")
    metadata = {
        "version": args.version,
        "platform": args.platform,
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=src, text=True).strip(),
        "go_build_info": {name: subprocess.check_output(["go", "version", "-m", str((args.build_dir / name).resolve())], text=True)
                          for name in binaries},
    }
    os_name, arch = args.platform.split("_")
    for info in metadata["go_build_info"].values():
        if f"GOOS={os_name}\n" not in info or f"GOARCH={arch}\n" not in info:
            raise ValueError("binary target does not match archive platform")
        if "GOFIPS140=v" not in info or "CGO_ENABLED=0" not in info:
            raise ValueError("release requires a versioned FIPS module and CGO_ENABLED=0")
    (args.build_dir / "BUILD-INFO.json").write_text(json.dumps(metadata, indent=2) + "\n")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    name = f"trustedcourier_{args.version}_{args.platform}"
    archive = args.output_dir / f"{name}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for item in binaries + ["SHA256SUMS", "BUILD-INFO.json"]:
            tar.add(args.build_dir / item, arcname=f"{name}/{item}")
        tar.add(src / "LICENSE", arcname=f"{name}/LICENSE")
        tar.add(src / "README.md", arcname=f"{name}/README.md")
        if args.platform.startswith("linux_"):
            for item in PLUGIN_FILES:
                if item.endswith(".claude-plugin/plugin.json"):
                    # Give the distributed plugin this release's version without
                    # changing the development checkout's manifest.
                    manifest = json.loads((src / item).read_text())
                    manifest["version"] = args.version.removeprefix("v")
                    data = (json.dumps(manifest, indent=2) + "\n").encode()
                    info = tar.gettarinfo(str(src / item), arcname=f"{name}/{item}")
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
                else:
                    tar.add(src / item, arcname=f"{name}/{item}")
    print(archive)


if __name__ == "__main__":
    main()
