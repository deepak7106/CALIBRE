"""Bounded, static analysis for downloaded files.

The analyzer accepts bytes (or a file path) and never writes, imports, or
executes the downloaded content.  Archive inspection is deliberately bounded
to make ZIP bombs and oversized browser downloads cheap to reject.
"""

from __future__ import annotations

import hashlib
import math
import re
import struct
import zipfile
from pathlib import Path
from typing import BinaryIO

from pydantic import BaseModel, ConfigDict, Field


class DownloadAnalyzerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_file_bytes: int = Field(default=50 * 1024 * 1024, gt=0)
    max_archive_members: int = Field(default=2_000, gt=0)
    max_member_bytes: int = Field(default=10 * 1024 * 1024, gt=0)
    max_archive_uncompressed_bytes: int = Field(default=100 * 1024 * 1024, gt=0)
    max_compression_ratio: float = Field(default=200.0, gt=0)
    max_static_string_bytes: int = Field(default=5 * 1024 * 1024, gt=0)
    max_static_strings: int = Field(default=200, gt=0)


class ArchiveLimits(BaseModel):
    members: int = 0
    uncompressed_bytes: int = 0
    limited: bool = False
    reasons: list[str] = Field(default_factory=list)


class DownloadAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filename: str
    size_bytes: int
    sha256: str
    detected_type: str
    declared_content_type: str | None = None
    extension: str
    extension_mismatch: bool = False
    pdf_indicators: list[str] = Field(default_factory=list)
    office_macro: bool = False
    office_external_references: list[str] = Field(default_factory=list)
    archive_limits: ArchiveLimits | None = None
    pe_strings: list[str] = Field(default_factory=list)
    pe_entropy: float | None = None
    indicators: list[str] = Field(default_factory=list)


_EXTENSIONS = {
    "pdf": {".pdf"},
    "zip": {".zip"},
    "office": {".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx", ".xltm", ".pptx", ".pptm", ".potx", ".potm"},
    "pe": {".exe", ".dll", ".scr", ".sys", ".cpl", ".ocx"},
    "text": {".txt", ".csv", ".log", ".json", ".xml", ".html", ".htm", ".js", ".css", ".md"},
    "image": {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico", ".tif", ".tiff"},
}


def _magic(data: bytes) -> str:
    if data.startswith(b"%PDF-"):
        return "pdf"
    if data.startswith(b"MZ") and len(data) >= 0x40:
        return "pe"
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06") or data.startswith(b"PK\x07\x08"):
        return "zip"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if data.startswith(b"BM"):
        return "image/bmp"
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "image/webp"
    if data.startswith(b"\x00\x00\x01\x00"):
        return "image/ico"
    if data.startswith((b"II*\x00", b"MM\x00*")):
        return "image/tiff"
    sample = data[:8192]
    if not sample:
        return "empty"
    try:
        sample.decode("utf-8")
        if b"\x00" not in sample:
            return "text"
    except UnicodeDecodeError:
        pass
    return "unknown"


def _extension(name: str) -> str:
    return Path(name).suffix.lower()


def _mismatch(kind: str, extension: str) -> bool:
    if kind == "image/png":
        expected = {".png"}
    elif kind.startswith("image/"):
        expected = {f".{kind[6:]}"}
        if kind == "image/jpeg":
            expected.add(".jpg")
        if kind == "image/tiff":
            expected.update({".tif", ".tiff"})
    else:
        expected = _EXTENSIONS.get(kind, set())
    return bool(extension and expected and extension not in expected)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts if count)


def _pe_strings(data: bytes, config: DownloadAnalyzerConfig) -> list[str]:
    sample = data[: config.max_static_string_bytes]
    found = re.findall(rb"[\x20-\x7e]{5,}", sample)
    return [item.decode("ascii", "replace")[:512] for item in found[: config.max_static_strings]]


def _archive_details(data: bytes, config: DownloadAnalyzerConfig) -> tuple[ArchiveLimits, bool, bool, list[str]]:
    limits = ArchiveLimits()
    office = False
    macro = False
    external: list[str] = []
    try:
        with zipfile.ZipFile(__import__("io").BytesIO(data)) as archive:
            names = archive.namelist()
            limits.members = len(names)
            if len(names) > config.max_archive_members:
                limits.limited = True
                limits.reasons.append("member_count")
            office = "[Content_Types].xml" in names and any(
                name.startswith(("word/", "xl/", "ppt/")) for name in names
            ) or any(
                name.startswith(("word/", "xl/", "ppt/")) for name in names
            )
            macro = any(name.lower().endswith("vbaproject.bin") for name in names)
            total = 0
            for info in archive.infolist()[: config.max_archive_members]:
                total += info.file_size
                if info.file_size > config.max_member_bytes:
                    limits.limited = True
                    limits.reasons.append("member_size")
                compressed = max(info.compress_size, 1)
                if info.file_size / compressed > config.max_compression_ratio:
                    limits.limited = True
                    limits.reasons.append("compression_ratio")
                if total > config.max_archive_uncompressed_bytes:
                    limits.limited = True
                    limits.reasons.append("uncompressed_size")
                    break
                if office and info.file_size <= min(config.max_member_bytes, 2 * 1024 * 1024) and info.filename.lower().endswith((".xml", ".rels", ".bin")):
                    # Read only bounded members; macro payloads are identified by
                    # names and markers, never loaded as executable code.
                    with archive.open(info) as member:
                        content = member.read(min(config.max_member_bytes, 2 * 1024 * 1024))
                    lower = content.lower()
                    if b"external" in lower or b"targetmode=\"external\"" in lower:
                        external.append(info.filename)
            limits.uncompressed_bytes = min(total, config.max_archive_uncompressed_bytes)
    except (zipfile.BadZipFile, OSError, RuntimeError, ValueError):
        return limits, False, False, []
    return limits, office, macro, sorted(set(external))


def analyze_download(
    content: bytes | bytearray | memoryview | str | Path | BinaryIO,
    filename: str | None = None,
    *,
    declared_content_type: str | None = None,
    config: DownloadAnalyzerConfig | dict | None = None,
) -> DownloadAnalysis:
    """Return static findings for a downloaded file without executing it."""
    config = DownloadAnalyzerConfig.model_validate(config or {})
    if isinstance(content, (str, Path)):
        path = Path(content)
        filename = filename or path.name
        with path.open("rb") as handle:
            raw = handle.read(config.max_file_bytes + 1)
    elif hasattr(content, "read"):
        raw = content.read(config.max_file_bytes + 1)
    else:
        raw = bytes(content)
    if len(raw) > config.max_file_bytes:
        raw = raw[: config.max_file_bytes]
        too_large = True
    else:
        too_large = False
    name = filename or "download"
    kind = _magic(raw)
    extension = _extension(name)
    mismatch = False
    pdf_indicators: list[str] = []
    if kind == "pdf":
        for marker in (b"/JavaScript", b"/JS", b"/OpenAction", b"/AA", b"/Launch", b"/EmbeddedFile", b"/URI"):
            if marker in raw:
                pdf_indicators.append(marker.decode("ascii"))
    archive_limits = None
    office_macro = False
    external: list[str] = []
    if kind == "zip":
        archive_limits, _office, office_macro, external = _archive_details(raw, config)
        if _office:
            kind = "office"
    mismatch = _mismatch(kind, extension)
    indicators: list[str] = []
    if too_large:
        indicators.append("file_size_limit")
    if mismatch:
        indicators.append("extension_mismatch")
    if kind == "pe":
        indicators.append("pe_file")
    if pdf_indicators:
        indicators.append("pdf_active_content")
    if office_macro:
        indicators.append("office_macro")
    if external:
        indicators.append("office_external_reference")
    if archive_limits and archive_limits.limited:
        indicators.append("archive_limit")
    return DownloadAnalysis(
        filename=name, size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
        detected_type=kind, declared_content_type=declared_content_type,
        extension=extension, extension_mismatch=mismatch,
        pdf_indicators=pdf_indicators, office_macro=office_macro,
        office_external_references=external, archive_limits=archive_limits,
        pe_strings=_pe_strings(raw, config) if kind == "pe" else [],
        pe_entropy=_entropy(raw) if kind == "pe" else None, indicators=indicators,
    )
