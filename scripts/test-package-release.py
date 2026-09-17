#!/usr/bin/env python3
"""Exercise packaging success and refusal paths against real built binaries."""
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

src = Path(__file__).resolve().parent.parent
build = Path(sys.argv[1]).resolve()
platform = sys.argv[2]
with tempfile.TemporaryDirectory(prefix="tc-release-test-") as tmp:
    tmp = Path(tmp)
    copied = tmp / "build"
    shutil.copytree(build, copied)
    out = tmp / "out"

    def package(version, target=platform, succeeds=True):
        result = subprocess.run([sys.executable, str(src / "scripts/package-release.py"),
                                 version, target, str(copied), str(out)], capture_output=True, text=True)
        if (result.returncode == 0) != succeeds:
            raise AssertionError(result.stdout + result.stderr)

    package("v1.2.3-rc.1")
    archive = out / f"trustedcourier_v1.2.3-rc.1_{platform}.tar.gz"
    prefix = f"trustedcourier_v1.2.3-rc.1_{platform}/"
    with tarfile.open(archive) as tar:
        assert set(tar.getnames()) == {prefix + name for name in
                                      ["tc", "openbao-plugin", "SHA256SUMS", "BUILD-INFO.json", "LICENSE", "README.md"]}
        for name in ["tc", "openbao-plugin"]:
            data = tar.extractfile(prefix + name).read()
            assert hashlib.sha256(data).digest() == hashlib.sha256((build / name).read_bytes()).digest()
            assert tar.getmember(prefix + name).mode & 0o111
        metadata = json.load(tar.extractfile(prefix + "BUILD-INFO.json"))
        assert metadata["version"] == "v1.2.3-rc.1" and metadata["platform"] == platform
    for invalid in ["../bad", "v01.2.3", "v1.2", "v1.2.3-01", "v1.2.3\nother"]:
        package(invalid, succeeds=False)
    wrong = "darwin_arm64" if platform != "darwin_arm64" else "linux_amd64"
    package("v1.2.3", wrong, succeeds=False)
    with (copied / "tc").open("ab") as binary:
        binary.write(b"tampered")
    package("v1.2.3", succeeds=False)
print("package success, contents, modes, metadata, invalid tags, target mismatch, and tamper rejection: PASS")
