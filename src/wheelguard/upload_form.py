"""Parse bounded publishing requests without buffering distribution files."""

import base64
import hashlib
import re
from collections.abc import AsyncGenerator
from contextlib import aclosing
from typing import Any

from python_multipart import MultipartParser
from python_multipart.exceptions import MultipartParseError
from python_multipart.multipart import parse_options_header

CHUNK_SIZE = 64 * 1024
PART_SIZE = 5 * 1024 * 1024
FORM_LIMIT = 1024 * 1024


class UploadError(Exception):
    """Report a safe publisher-facing error."""

    def __init__(self, message: str, status: int = 400) -> None:
        """Attach an HTTP status to a validation error."""
        super().__init__(message)
        self.status = status


async def stream_bytes(stream: Any) -> AsyncGenerator[bytes]:
    """Read a Workers stream in bounded chunks, cancelling on early exit."""
    reader = stream.getReader()
    finished = False
    try:
        while True:
            result = await reader.read()
            if result.done:
                finished = True
                break
            value = result.value
            # Slice before crossing the JS/Python boundary to bound Python allocations.
            for offset in range(0, int(value.byteLength), CHUNK_SIZE):
                yield value.subarray(offset, offset + CHUNK_SIZE).to_bytes()
    finally:
        if not finished:
            await reader.cancel()
        reader.releaseLock()


class UploadForm:
    """Receive one distribution plus bounded legacy upload fields."""

    def __init__(self, content_type: str, maximum_bytes: int) -> None:
        """Configure a streaming multipart parser and digest calculation."""
        media_type, options = parse_options_header(content_type)
        boundary = options.get(b"boundary", b"")
        if media_type != b"multipart/form-data" or not boundary or len(boundary) > 200:
            raise UploadError("Expected multipart/form-data with a boundary", 415)
        self.maximum_bytes = maximum_bytes
        self.fields: dict[str, list[str]] = {}
        self.filename = ""
        self.size = 0
        self.hash = hashlib.sha256()
        self.md5 = hashlib.md5(usedforsecurity=False)
        self.blake2 = hashlib.blake2b(digest_size=32)
        self.pending = bytearray()
        self.finished = False
        self._name = ""
        self._file = False
        self._field = bytearray()
        self._header_name = bytearray()
        self._header_value = bytearray()
        self._headers: dict[bytes, bytes] = {}
        self._overhead = 0
        self.parser = MultipartParser(
            boundary,
            {
                "on_part_begin": self._part_begin,
                "on_header_field": self._header_field,
                "on_header_value": self._header_data,
                "on_header_end": self._header_end,
                "on_headers_finished": self._headers_finished,
                "on_part_data": self._part_data,
                "on_part_end": self._part_end,
                "on_end": self._end,
            },
        )

    def _count(self, size: int) -> None:
        self._overhead += size
        if self._overhead > FORM_LIMIT:
            raise UploadError("Upload metadata exceeds 1 MiB", 413)

    def _part_begin(self) -> None:
        self._count(1)
        self._headers = {}
        self._field = bytearray()

    def _header_field(self, data: bytes, start: int, end: int) -> None:
        self._count(end - start)
        self._header_name.extend(data[start:end])

    def _header_data(self, data: bytes, start: int, end: int) -> None:
        self._count(end - start)
        self._header_value.extend(data[start:end])

    def _header_end(self) -> None:
        name = bytes(self._header_name).lower()
        if name in self._headers:
            raise UploadError("Duplicate multipart header")
        self._headers[name] = bytes(self._header_value)
        self._header_name.clear()
        self._header_value.clear()

    def _headers_finished(self) -> None:
        disposition, options = parse_options_header(self._headers.get(b"content-disposition"))
        if disposition != b"form-data" or b"name" not in options:
            raise UploadError("Invalid multipart field")
        try:
            self._name = options[b"name"].decode("utf-8")
            self._file = b"filename" in options
            if self._file:
                if self._name != "content" or self.filename:
                    raise UploadError("Upload exactly one content file per request")
                self.filename = options[b"filename"].decode("utf-8")
                if len(self.filename) > 255 or not re.fullmatch(r"[A-Za-z0-9_.+-]+", self.filename):
                    raise UploadError("Invalid distribution filename")
            elif self._name == "content":
                raise UploadError("The content field must have a filename")
        except UnicodeDecodeError as error:
            raise UploadError("Multipart field names must be UTF-8") from error

    def _part_data(self, data: bytes, start: int, end: int) -> None:
        if self._file:
            self.size += end - start
            if self.size > self.maximum_bytes:
                raise UploadError("Artifact exceeds configured size limit", 413)
            chunk = data[start:end]
            self.hash.update(chunk)
            self.md5.update(chunk)
            self.blake2.update(chunk)
            self.pending.extend(chunk)
        else:
            self._count(end - start)
            self._field.extend(data[start:end])

    def _part_end(self) -> None:
        if not self._file:
            try:
                self.fields.setdefault(self._name, []).append(self._field.decode("utf-8"))
            except UnicodeDecodeError as error:
                raise UploadError("Upload metadata must be UTF-8") from error

    def _end(self) -> None:
        self.finished = True

    def field(self, name: str, *, required: bool = True) -> str:
        """Return one unambiguous scalar field."""
        values = self.fields.get(name, [])
        if not values and not required:
            return ""
        if len(values) != 1:
            raise UploadError(f"Expected exactly one {name} field")
        return values[0]

    def validate(self) -> None:
        """Verify framing and the legacy protocol after the stream completes."""
        if not self.finished or not self.filename or not self.size:
            raise UploadError("Incomplete upload or empty distribution")
        if self.field(":action") != "file_upload" or self.field("protocol_version") != "1":
            raise UploadError("Unsupported upload protocol")
        digest = self.field("sha256_digest", required=False)
        if digest and digest.lower() != self.hash.hexdigest():
            raise UploadError("Artifact SHA-256 does not match supplied digest")
        md5 = self.field("md5_digest", required=False)
        if md5 and md5 not in {self.md5.hexdigest(), base64.urlsafe_b64encode(self.md5.digest()).decode().rstrip("=")}:
            raise UploadError("Artifact MD5 does not match supplied digest")
        blake2 = self.field("blake2_256_digest", required=False)
        if blake2 and blake2.lower() != self.blake2.hexdigest():
            raise UploadError("Artifact BLAKE2 does not match supplied digest")
        if "attestations" in self.fields:
            raise UploadError("Attestations are not supported; publish without attestations")


async def receive_upload(request: Any, bucket: Any, key: str, maximum_bytes: int) -> UploadForm:
    """Stream into a unique R2 multipart object, aborting incomplete uploads."""
    form = UploadForm(str(request.headers.get("content-type") or ""), maximum_bytes)
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            size = int(declared)
        except ValueError as error:
            raise UploadError("Invalid Content-Length") from error
        if size < 0 or size > maximum_bytes + FORM_LIMIT:
            raise UploadError("Upload exceeds configured size limit", 413)
    if request.body is None:
        raise UploadError("Missing upload body")
    upload = await bucket.createMultipartUpload(key)
    parts: list[Any] = []
    complete = False
    total = 0
    try:
        async with aclosing(stream_bytes(request.body)) as chunks:
            async for chunk in chunks:
                total += len(chunk)
                if total > maximum_bytes + FORM_LIMIT:
                    raise UploadError("Upload exceeds configured size limit", 413)
                try:
                    form.parser.write(chunk)
                except MultipartParseError as error:
                    raise UploadError("Invalid multipart upload") from error
                while len(form.pending) >= PART_SIZE:
                    data = bytes(form.pending[:PART_SIZE])
                    del form.pending[:PART_SIZE]
                    parts.append(await upload.uploadPart(len(parts) + 1, data))
        form.validate()
        if form.pending:
            parts.append(await upload.uploadPart(len(parts) + 1, bytes(form.pending)))
            form.pending.clear()
        await upload.complete(parts)
        complete = True
        return form
    finally:
        if not complete:
            await upload.abort()
