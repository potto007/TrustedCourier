#!/usr/bin/env python3
"""Package an already built release without reading any local deployment state."""
import argparse
import hashlib
import json
import re
import subprocess
import tarfile
from pathlib import Path

VERSION = r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?:[0-9A-Za-z-]+)(?:\.[0-9A-Za-z-]+)*)?"


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
    # Verify exactly the two expected binaries, not arbitrary paths from a manifest.
    expected = "".join(f"{hashlib.sha256((args.build_dir / name).read_bytes()).hexdigest()}  {name}\n"
                       for name in ("tc", "openbao-plugin"))
    if (args.build_dir / "SHA256SUMS").read_text() != expected:
        raise ValueError("binary checksum verification failed")
    metadata = {
        "version": args.version,
        "platform": args.platform,
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=src, text=True).strip(),
        "go_build_info": {name: subprocess.check_output(["go", "version", "-m", str((args.build_dir / name).resolve())], text=True)
                          for name in ("tc", "openbao-plugin")},
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
        for item in ("tc", "openbao-plugin", "SHA256SUMS", "BUILD-INFO.json"):
            tar.add(args.build_dir / item, arcname=f"{name}/{item}")
        tar.add(src / "LICENSE", arcname=f"{name}/LICENSE")
        tar.add(src / "README.md", arcname=f"{name}/README.md")
    print(archive)


if __name__ == "__main__":
    main()
