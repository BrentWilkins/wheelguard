"""Test Azure Blob's immutable multipart adapter."""

import asyncio

from wheelguard.azure_storage import AzureMultipartUpload


class Blob:
    """Record staged and committed blocks."""

    def __init__(self) -> None:
        self.staged: list[tuple[str, bytes]] = []
        self.committed: list[str] = []

    async def stage_block(self, block_id: str, data: bytes, *, length: int) -> None:
        assert length == len(data)
        self.staged.append((block_id, data))

    async def commit_block_list(self, blocks: list[str]) -> None:
        self.committed = blocks


def test_concurrent_uploads_use_isolated_block_ids() -> None:
    """Prevent two replicas staging the same digest from replacing each other's blocks."""

    async def exercise() -> None:
        blob = Blob()
        first, second = AzureMultipartUpload(blob), AzureMultipartUpload(blob)
        first_part = await first.uploadPart(1, b"first")
        second_part = await second.uploadPart(1, b"second")
        assert first_part.block_id != second_part.block_id
        await first.complete([first_part])
        assert blob.committed == [first_part.block_id]

    asyncio.run(exercise())


def test_changed_part_list_is_rejected() -> None:
    """Commit only the exact ordered list returned by the active upload."""

    async def exercise() -> None:
        blob = Blob()
        upload = AzureMultipartUpload(blob)
        part = await upload.uploadPart(1, b"data")
        try:
            await upload.complete([])
        except ValueError as error:
            assert "changed" in str(error)
        else:
            raise AssertionError("changed block list was accepted")
        assert isinstance(part.part_number, int)

    asyncio.run(exercise())
