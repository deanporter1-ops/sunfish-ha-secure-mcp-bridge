"""Pinned official baseline-musl release; no installer or archive extraction."""

import hashlib
import io
import os
import stat
import sys
import tarfile
import urllib.request

RELEASE = "v1.18.34"
ARTIFACT = "opencode-linux-x64-baseline-musl.tar.gz"
SHA256 = "4c3717c081d06b842172af1b0dd9f4dc54335865e141db9c7059ccd1d8c1b451"
ARCHIVE_SIZE = 63031633
MEMBER_NAME = "opencode"
BINARY_SIZE = 196049184
BINARY_SHA256 = "4fa437184846977f1849ffb65fc19d32686dec85a455df3d37f69a2993f22182"
URL = f"https://github.com/anomalyco/opencode/releases/download/{RELEASE}/{ARTIFACT}"


def validate_payload(payload):
    if len(payload) != ARCHIVE_SIZE or hashlib.sha256(payload).hexdigest() != SHA256:
        raise RuntimeError("Pinned OpenCode release checksum/size mismatch")
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) != 1:
            raise RuntimeError("Unexpected OpenCode archive member count")
        member = members[0]
        if (member.name != MEMBER_NAME or not member.isfile() or member.issparse()
                or member.linkname or member.size != BINARY_SIZE or member.mode != 0o755):
            raise RuntimeError("Unexpected OpenCode archive layout")
        with archive.extractfile(member) as handle:
            binary = handle.read(BINARY_SIZE + 1)
    if len(binary) != BINARY_SIZE or hashlib.sha256(binary).hexdigest() != BINARY_SHA256:
        raise RuntimeError("OpenCode member checksum/size mismatch")
    # ELF64, little-endian, current ELF version, native Linux amd64 executable.
    if (binary[:7] != b"\x7fELF\x02\x01\x01" or binary[16:20] != b"\x02\x00\x3e\x00"
            or binary[20:24] != b"\x01\x00\x00\x00"):
        raise RuntimeError("Expected native Linux amd64 ELF executable")
    return binary


def verify_artifact():
    request = urllib.request.Request(URL, headers={"User-Agent": "Sunfish-OpenCode-Build"})
    with urllib.request.urlopen(request, timeout=120) as response:
        payload = response.read(ARCHIVE_SIZE + 1)
    binary = validate_payload(payload)
    print(f"Verified official {RELEASE} baseline-musl: sha256:{SHA256}")
    print(f"Verified exact regular member: {MEMBER_NAME}, ELF64 amd64, {BINARY_SIZE} bytes")
    return binary


def install_artifact(binary):
    destination = "/usr/local/bin/opencode"
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(binary)
    os.chown(destination, 0, 0)
    os.chmod(destination, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR |
             stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["--verify-only"]):
        raise SystemExit("Only --verify-only is supported outside an image build")
    verified = verify_artifact()
    if not sys.argv[1:]:
        install_artifact(verified)
