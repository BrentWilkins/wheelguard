"""Inspect distribution metadata from R2 without loading or executing packages."""

import io
import re
import struct
import tarfile
import zipfile
import zlib
from contextlib import aclosing, suppress
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name, parse_sdist_filename, parse_wheel_filename
from packaging.version import InvalidVersion, Version

from wheelguard.upload_form import CHUNK_SIZE, UploadError, UploadForm, stream_bytes

METADATA_LIMIT = 1024 * 1024
CHANGELOG_LIMIT = 256 * 1024


@dataclass(frozen=True, slots=True)
class ChangelogSnapshot:
    """Hold bounded release notes captured from a source distribution."""

    content: str
    format: str


@dataclass(frozen=True, slots=True)
class DistributionMetadata:
    """Describe validated identity and optional human-facing release notes."""

    name: str
    version: str
    requires_python: str | None
    changelog: ChangelogSnapshot | None


def _changelog_format(path: str) -> str | None:
    parts = path.split("/")
    if len(parts) != 2:
        return None
    names = {
        "changelog.md": "markdown",
        "changes.md": "markdown",
        "history.md": "markdown",
        "release-notes.md": "markdown",
        "changelog.rst": "rst",
        "changes.rst": "rst",
        "history.rst": "rst",
        "changelog.txt": "text",
        "changes.txt": "text",
    }
    return names.get(parts[1].casefold())


async def _range(bucket: Any, key: str, offset: int, length: int) -> bytes:
    if length <= 0:
        return b""
    obj = await bucket.get(key, range={"offset": offset, "length": length})
    if obj is None:
        raise UploadError("Uploaded object is unavailable", 503)
    data = await obj.arrayBuffer()
    result = data.to_bytes() if hasattr(data, "to_bytes") else bytes(data)
    if len(result) != length:
        raise UploadError("Uploaded object is truncated")
    return result


async def _zip_member(bucket: Any, key: str, directory_offset: int, info: zipfile.ZipInfo, limit: int) -> bytes:
    """Read and verify one bounded member described by a ZIP central directory."""
    offset = info.header_offset + directory_offset
    if info.file_size > limit or info.compress_size > limit or info.flag_bits & 1:
        raise UploadError("Invalid or oversized distribution metadata")
    header = await _range(bucket, key, offset, 30)
    if header[:4] != b"PK\x03\x04":
        raise UploadError("Invalid ZIP metadata header")
    name_size, extra_size = struct.unpack("<HH", header[26:30])
    start = offset + 30 + name_size + extra_size
    if start + info.compress_size > directory_offset:
        raise UploadError("Invalid ZIP metadata offset")
    member_name = await _range(bucket, key, offset + 30, name_size)
    if member_name != info.filename.encode("utf-8" if info.flag_bits & 0x800 else "cp437"):
        raise UploadError("ZIP local and central metadata filenames differ")
    compressed = await _range(bucket, key, start, info.compress_size)
    if info.compress_type == zipfile.ZIP_STORED:
        content = compressed
    elif info.compress_type == zipfile.ZIP_DEFLATED:
        try:
            decoder = zlib.decompressobj(-15)
            content = decoder.decompress(compressed, limit + 1)
            if not decoder.eof or decoder.unused_data:
                raise UploadError("Invalid compressed metadata")
        except zlib.error as error:
            raise UploadError("Invalid compressed metadata") from error
    else:
        raise UploadError("Unsupported ZIP metadata compression")
    if len(content) != info.file_size or zlib.crc32(content) != info.CRC:
        raise UploadError("Distribution metadata checksum mismatch")
    return content


async def _zip_metadata(bucket: Any, key: str, size: int, *, wheel: bool) -> tuple[bytes, ChangelogSnapshot | None]:
    # Fetch only the central directory and the metadata member. zipfile parses a
    # small synthetic archive; offsets are adjusted back to the original object.
    tail_offset = max(0, size - 65_557)
    tail = await _range(bucket, key, tail_offset, size - tail_offset)
    end = tail.rfind(b"PK\x05\x06")
    if end < 0 or len(tail) - end < 22:
        raise UploadError("Invalid ZIP distribution")
    _, disk, directory_disk, disk_entries, entries, directory_size, directory_offset, comment_size = struct.unpack(
        "<4s4H2LH", tail[end : end + 22]
    )
    if (
        disk
        or directory_disk
        or disk_entries != entries
        or entries == 65535
        or directory_size > METADATA_LIMIT
        or directory_offset + directory_size != tail_offset + end
        or len(tail) - end != 22 + comment_size
    ):
        raise UploadError("Unsupported or invalid ZIP directory (maximum 1 MiB; no ZIP64 directory)")
    directory = await _range(bucket, key, directory_offset, directory_size)
    synthetic = directory + tail[end:]
    try:
        with zipfile.ZipFile(io.BytesIO(synthetic)) as archive:
            candidates = [
                info
                for info in archive.infolist()
                if (info.filename.endswith(".dist-info/METADATA") if wheel else info.filename.endswith("/PKG-INFO"))
                and len(info.filename.split("/")) == 2
            ]
            if len(candidates) != 1:
                raise UploadError("Distribution must contain exactly one top-level metadata file")
            metadata_info = candidates[0]
            changelog_info = next(
                (info for info in archive.infolist() if not wheel and _changelog_format(info.filename)),
                None,
            )
    except (zipfile.BadZipFile, ValueError) as error:
        raise UploadError("Invalid ZIP distribution") from error
    metadata = await _zip_member(bucket, key, directory_offset, metadata_info, METADATA_LIMIT)
    changelog = None
    if changelog_info is not None and changelog_info.file_size <= CHANGELOG_LIMIT:
        raw = await _zip_member(bucket, key, directory_offset, changelog_info, CHANGELOG_LIMIT)
        with suppress(UnicodeDecodeError):
            changelog = ChangelogSnapshot(raw.decode("utf-8"), _changelog_format(changelog_info.filename) or "text")
    return metadata, changelog


class _TarMetadata:
    """Scan tar blocks with bounded storage, without extracting any paths."""

    def __init__(self) -> None:
        self.buffer = bytearray()
        self.remaining = 0
        self.padding = 0
        self.capture: str | None = None
        self.metadata: bytes | None = None
        self.changelog: ChangelogSnapshot | None = None
        self.changelog_format: str | None = None
        self.member = bytearray()
        self.ended = False

    def feed(self, data: bytes) -> None:
        self.buffer.extend(data)
        while self.buffer:
            if self.remaining:
                count = min(self.remaining, len(self.buffer))
                if self.capture is not None:
                    self.member.extend(self.buffer[:count])
                del self.buffer[:count]
                self.remaining -= count
                if self.remaining:
                    return
                if self.capture == "metadata":
                    self.metadata = bytes(self.member)
                elif self.capture == "changelog":
                    try:
                        self.changelog = ChangelogSnapshot(
                            bytes(self.member).decode("utf-8"), self.changelog_format or "text"
                        )
                    except UnicodeDecodeError:
                        self.changelog = None
            if self.padding:
                count = min(self.padding, len(self.buffer))
                del self.buffer[:count]
                self.padding -= count
                if self.padding:
                    return
            if len(self.buffer) < 512:
                return
            header = bytes(self.buffer[:512])
            del self.buffer[:512]
            if header == b"\0" * 512:
                self.ended = True
                continue
            if self.ended:
                raise UploadError("Unexpected data after tar end marker")
            try:
                info = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
            except (tarfile.HeaderError, UnicodeError) as error:
                raise UploadError("Invalid source distribution tar header") from error
            if info.size < 0:
                raise UploadError("Invalid tar member size")
            is_metadata = info.name.endswith("/PKG-INFO") and len(info.name.split("/")) == 2
            changelog_format = _changelog_format(info.name)
            self.capture = "metadata" if is_metadata else None
            if is_metadata and (not info.isfile() or info.size > METADATA_LIMIT or self.metadata is not None):
                raise UploadError("Invalid, duplicate, or oversized source metadata")
            if (
                self.capture is None
                and changelog_format is not None
                and self.changelog is None
                and info.isfile()
                and info.size <= CHANGELOG_LIMIT
            ):
                self.capture = "changelog"
                self.changelog_format = changelog_format
            self.member.clear()
            self.remaining = info.size
            self.padding = (-info.size) % 512
            if self.capture == "metadata" and not info.size:
                raise UploadError("Empty source metadata")


async def _tar_metadata(bucket: Any, key: str, size: int) -> tuple[bytes, ChangelogSnapshot | None]:
    decoder = zlib.decompressobj(31)
    scanner = _TarMetadata()
    expanded = 0
    obj = await bucket.get(key)
    if obj is None:
        raise UploadError("Uploaded object is unavailable", 503)
    try:
        async with aclosing(stream_bytes(obj.body)) as chunks:
            async for compressed in chunks:
                while compressed:
                    data = decoder.decompress(compressed, CHUNK_SIZE)
                    if decoder.unused_data:
                        raise UploadError("Unexpected data after gzip end marker")
                    compressed = decoder.unconsumed_tail
                    expanded += len(data)
                    if expanded > min(1024 * 1024 * 1024, max(size * 100, METADATA_LIMIT)):
                        raise UploadError("Source distribution expands beyond inspection limit", 413)
                    scanner.feed(data)
        if not decoder.eof or decoder.unused_data or scanner.remaining or not scanner.ended:
            raise UploadError("Truncated or invalid source distribution")
    except zlib.error as error:
        raise UploadError("Invalid gzip source distribution") from error
    if scanner.metadata is None:
        raise UploadError("Source distribution has no top-level PKG-INFO")
    return scanner.metadata, scanner.changelog


async def validate_distribution(bucket: Any, key: str, form: UploadForm) -> DistributionMetadata:
    """Match filename, upload fields, and embedded core metadata."""
    try:
        if form.filename.endswith(".whl"):
            name, version, _, _ = parse_wheel_filename(form.filename)
        else:
            name, version = parse_sdist_filename(form.filename)
        if canonicalize_name(form.field("name"), validate=True) != name or Version(form.field("version")) != version:
            raise UploadError("Upload name/version does not match distribution filename")
    except ValueError as error:
        raise UploadError("Invalid distribution filename, name, or version") from error
    if len(name) > 200:
        raise UploadError("Project name exceeds 200 characters")
    filetype = form.field("filetype", required=False)
    if filetype and filetype != ("bdist_wheel" if form.filename.endswith(".whl") else "sdist"):
        raise UploadError("Upload filetype does not match distribution filename")
    if form.filename.endswith(".tar.gz"):
        metadata, changelog = await _tar_metadata(bucket, key, form.size)
    else:
        metadata, changelog = await _zip_metadata(bucket, key, form.size, wheel=form.filename.endswith(".whl"))
    message = BytesParser(policy=policy.default).parsebytes(metadata, headersonly=True)
    if message.defects:
        raise UploadError("Malformed distribution metadata")
    for field in ("Metadata-Version", "Name", "Version"):
        if len(message.get_all(field, [])) != 1:
            raise UploadError(f"Distribution metadata must contain exactly one {field}")
    if not re.fullmatch(r"[1-9][0-9]*\.[0-9]+", str(message["Metadata-Version"])):
        raise UploadError("Invalid Metadata-Version")
    try:
        if (
            canonicalize_name(str(message["Name"]), validate=True) != name
            or Version(str(message["Version"])) != version
        ):
            raise UploadError("Embedded metadata does not match distribution filename")
        values = message.get_all("Requires-Python", [])
        if len(values) > 1:
            raise UploadError("Duplicate Requires-Python metadata")
        requires_python = str(values[0]) if values else None
        if requires_python:
            SpecifierSet(requires_python)
    except (ValueError, InvalidVersion, InvalidSpecifier) as error:
        raise UploadError("Invalid distribution core metadata") from error
    return DistributionMetadata(str(name), str(version), requires_python, changelog)
