"""Fetch only pinned official OpenAI release artifacts; never run an installer."""

import hashlib
import io
import os
import sys
import tarfile
import urllib.request

RELEASE = "rust-v0.160.0"
ARTIFACTS = {
    "codex": (
        "codex-x86_64-unknown-linux-musl.tar.gz",
        "306865417d4ee7a927785852910a527f41e1e159add390ac5ae3accb67d44a13",
        "codex-x86_64-unknown-linux-musl",
    ),
    "bwrap": (
        "bwrap-x86_64-unknown-linux-musl.tar.gz",
        "1844535ea16d5454a6b5ee5df541c068ea8ddf1028ad3520255b16e05de3183d",
        "bwrap-x86_64-unknown-linux-musl",
    ),
}


def verify_artifact(artifact, expected_sha256, member_name):
    url = f"https://github.com/openai/codex/releases/download/{RELEASE}/{artifact}"
    request = urllib.request.Request(url, headers={"User-Agent": "Sunfish-Codex-Build"})
    with urllib.request.urlopen(request, timeout=120) as response:
        payload = response.read(200 * 1024 * 1024 + 1)
    if len(payload) > 200 * 1024 * 1024:
        raise RuntimeError("Release artifact exceeds build limit")
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise RuntimeError(f"Pinned checksum mismatch: {artifact}")
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        matches = [m for m in archive.getmembers() if m.name.lstrip("./") == member_name]
        if len(matches) != 1 or not matches[0].isfile():
            raise RuntimeError(f"Unexpected release archive layout: {artifact}")
        binary = archive.extractfile(matches[0]).read()
    if not binary.startswith(b"\x7fELF\x02\x01") or binary[18:20] != b"\x3e\x00":
        raise RuntimeError(f"Expected native Linux x86-64 ELF binary: {artifact}")
    print(f"Verified official {RELEASE} {artifact}: sha256:{expected_sha256}")
    return binary


def install_artifact(command, artifact, expected_sha256, member_name):
    binary = verify_artifact(artifact, expected_sha256, member_name)
    destination = f"/usr/local/bin/{command}"
    with open(destination, "wb") as handle:
        handle.write(binary)
    os.chmod(destination, 0o755)


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["--verify-only"]):
        raise SystemExit("Only --verify-only is supported outside an image build")
    for command, artifact in ARTIFACTS.items():
        if sys.argv[1:] == ["--verify-only"]:
            verify_artifact(*artifact)
        else:
            install_artifact(command, *artifact)
