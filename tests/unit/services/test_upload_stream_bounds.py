"""Upload request streaming boundary tests."""

import asyncio

import pytest
from starlette.requests import Request

from threat_hunting.api.workflow import _read_bounded_upload
from threat_hunting.services.uploads import UploadError


def _request(chunks: list[bytes], *, content_length: str | None = None) -> tuple[Request, list[int]]:
    seen: list[int] = []
    messages = [{"type": "http.request", "body": chunk, "more_body": index < len(chunks) - 1} for index, chunk in enumerate(chunks)]

    async def receive() -> dict[str, object]:
        seen.append(1)
        return messages.pop(0) if messages else {"type": "http.disconnect"}

    headers = [] if content_length is None else [(b"content-length", content_length.encode())]
    return Request({"type": "http", "method": "POST", "path": "/", "headers": headers}, receive), seen


def test_declared_oversize_rejected_before_stream_read() -> None:
    request, seen = _request([b"unused"], content_length="11")
    with pytest.raises(UploadError, match="per-file"):
        asyncio.run(_read_bounded_upload(request, 10))
    assert seen == []


@pytest.mark.parametrize("content_length", [None, "1", "invalid"])
def test_stream_hard_cap_rejects_missing_or_false_content_length(content_length: str | None) -> None:
    request, _ = _request([b"1234", b"5678", b"9"], content_length=content_length)
    with pytest.raises(UploadError, match="per-file"):
        asyncio.run(_read_bounded_upload(request, 8))
