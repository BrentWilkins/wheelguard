"""Azure Blob adapters for Wheelguard's bounded object-storage operations."""

from __future__ import annotations

import base64
import contextlib
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

from azure.core.exceptions import ResourceNotFoundError
from azure.identity.aio import DefaultAzureCredential
from azure.storage.blob.aio import BlobServiceClient, ContainerClient
from fastapi import Request


class ByteBuffer:
    """Expose the small Uint8Array surface used by shared upload validation."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self.byteLength = len(data)

    def subarray(self, start: int, end: int) -> ByteBuffer:
        """Return a bounded view copy."""
        return ByteBuffer(self._data[start:end])

    def to_bytes(self) -> bytes:
        """Return ordinary Python bytes."""
        return self._data

    def __bytes__(self) -> bytes:
        return self._data


class AsgiReader:
    """Adapt an ASGI request stream to the Workers reader contract."""

    def __init__(self, request: Request) -> None:
        self._iterator = request.stream().__aiter__()
        self._finished = False

    def getReader(self) -> AsgiReader:  # noqa: N802 - Workers-compatible API
        return self

    async def read(self) -> Any:
        """Read the next ASGI body fragment."""
        if self._finished:
            return SimpleNamespace(done=True, value=ByteBuffer(b""))
        try:
            chunk = await self._iterator.__anext__()
        except StopAsyncIteration:
            self._finished = True
            return SimpleNamespace(done=True, value=ByteBuffer(b""))
        return SimpleNamespace(done=False, value=ByteBuffer(chunk))

    async def cancel(self) -> None:
        """Close the request stream after an early validation failure."""
        self._finished = True
        close = getattr(self._iterator, "aclose", None)
        if close is not None:
            await close()

    def releaseLock(self) -> None:  # noqa: N802 - Workers-compatible API
        """Match the Workers reader lifecycle contract."""


class BlobReader:
    """Adapt an Azure streaming downloader to the Workers reader contract."""

    def __init__(self, downloader: Any) -> None:
        self._chunks = downloader.chunks().__aiter__()
        self._finished = False

    def getReader(self) -> BlobReader:  # noqa: N802
        return self

    async def read(self) -> Any:
        if self._finished:
            return SimpleNamespace(done=True, value=ByteBuffer(b""))
        try:
            chunk = await self._chunks.__anext__()
        except StopAsyncIteration:
            self._finished = True
            return SimpleNamespace(done=True, value=ByteBuffer(b""))
        return SimpleNamespace(done=False, value=ByteBuffer(bytes(chunk)))

    async def cancel(self) -> None:
        self._finished = True
        close = getattr(self._chunks, "aclose", None)
        if close is not None:
            await close()

    def releaseLock(self) -> None:  # noqa: N802
        pass


@dataclass(frozen=True, slots=True)
class AzurePart:
    """Identify one staged Azure block."""

    block_id: str
    part_number: int


class AzureMultipartUpload:
    """Stage blocks under a unique blob name and publish them atomically."""

    def __init__(self, blob: Any) -> None:
        self._blob = blob
        self._parts: list[AzurePart] = []
        self._upload_id = uuid4().hex

    async def uploadPart(self, number: int, data: bytes) -> AzurePart:  # noqa: N802
        if number != len(self._parts) + 1:
            raise ValueError("Blob blocks must be staged in order")
        block_id = base64.b64encode(f"{self._upload_id}:{number:08d}".encode()).decode()
        await self._blob.stage_block(block_id, data, length=len(data))
        part = AzurePart(block_id, number)
        self._parts.append(part)
        return part

    async def complete(self, parts: list[AzurePart]) -> None:
        if parts != self._parts:
            raise ValueError("Blob block list changed before commit")
        await self._blob.commit_block_list([part.block_id for part in parts])

    async def abort(self) -> None:
        # Uncommitted Azure blocks expire automatically and are never visible.
        self._parts.clear()


class AzureObject:
    """Expose one downloaded blob to shared range and streaming validators."""

    def __init__(self, downloader: Any) -> None:
        self._downloader = downloader
        self.size = int(downloader.properties.size)
        self.body = BlobReader(downloader)

    async def arrayBuffer(self) -> ByteBuffer:  # noqa: N802
        return ByteBuffer(await self._downloader.readall())

    async def iter_bytes(self) -> Any:
        """Yield download chunks to an ASGI streaming response."""
        async for chunk in self._downloader.chunks():
            yield bytes(chunk)


class AzureBlobBucket:
    """Provide the R2-like subset required by distribution validation."""

    def __init__(self, container: ContainerClient) -> None:
        self._container = container

    @classmethod
    def from_account_url(
        cls, account_url: str, container_name: str, credential: DefaultAzureCredential
    ) -> tuple[AzureBlobBucket, BlobServiceClient]:
        """Create a bucket and return its owning service client."""
        service = BlobServiceClient(account_url, credential=credential)
        return cls(service.get_container_client(container_name)), service

    async def createMultipartUpload(self, key: str) -> AzureMultipartUpload:  # noqa: N802
        return AzureMultipartUpload(self._container.get_blob_client(key))

    async def delete(self, key: str) -> None:
        with contextlib.suppress(ResourceNotFoundError):
            await self._container.delete_blob(key, delete_snapshots="include")

    async def get(self, key: str, **options: Any) -> AzureObject | None:
        range_value = options.get("range")
        offset: int | None = None
        length: int | None = None
        if isinstance(range_value, dict):
            offset = int(range_value["offset"])
            length = int(range_value["length"])
        try:
            downloader = await self._container.download_blob(key, offset=offset, length=length)
        except ResourceNotFoundError:
            return None
        return AzureObject(downloader)


def upload_request_adapter(request: Request) -> Any:
    """Expose a FastAPI request to the shared multipart receiver."""
    return SimpleNamespace(
        headers=request.headers, body=AsgiReader(request), method=request.method, url=str(request.url)
    )
