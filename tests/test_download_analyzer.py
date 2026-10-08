import io
import zipfile

from trustshield.browser import analyze_download


def _zip_files(files: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return stream.getvalue()


def test_pdf_hash_magic_indicators_and_extension_mismatch():
    result = analyze_download(
        b"%PDF-1.7\n/JavaScript /OpenAction /URI", "invoice.txt"
    )
    assert result.sha256
    assert result.detected_type == "pdf"
    assert result.extension_mismatch is True
    assert set(result.pdf_indicators) == {"/JavaScript", "/OpenAction", "/URI"}
    assert "pdf_active_content" in result.indicators


def test_office_zip_macro_and_external_reference_are_static_only():
    content = _zip_files({
        "[Content_Types].xml": b"<Types/>",
        "word/document.xml": b"<document/>",
        "word/vbaProject.bin": b"not executed",
        "word/_rels/document.xml.rels": b'TargetMode="External" Target="https://example.test"',
    })
    result = analyze_download(content, "invoice.docm")
    assert result.detected_type == "office"
    assert result.office_macro is True
    assert result.office_external_references == ["word/_rels/document.xml.rels"]
    assert "office_macro" in result.indicators


def test_archive_limits_prevent_large_member_reads():
    content = _zip_files({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"x" * 100})
    result = analyze_download(
        content, "invoice.docx",
        config={"max_member_bytes": 10, "max_archive_uncompressed_bytes": 20},
    )
    assert result.archive_limits is not None
    assert result.archive_limits.limited is True
    assert "archive_limit" in result.indicators


def test_images_text_and_pe_static_properties():
    image = analyze_download(b"\x89PNG\r\n\x1a\n", "pixel.png")
    assert image.detected_type == "image/png"
    text = analyze_download(b"hello, world\n", "notes.txt")
    assert text.detected_type == "text"
    pe = analyze_download(b"MZ" + b"A" * 100, "program.exe")
    assert pe.detected_type == "pe"
    assert "pe_file" in pe.indicators
    assert pe.pe_strings
    assert pe.pe_entropy is not None


def test_malformed_unsupported_and_oversized_files_are_safe():
    malformed = analyze_download(b"\x00\x01\x02", "unknown.bin")
    assert malformed.detected_type == "unknown"
    assert malformed.sha256

    oversized = analyze_download(
        b"A" * 32, "large.bin", config={"max_file_bytes": 8}
    )
    assert oversized.size_bytes == 8
    assert "file_size_limit" in oversized.indicators

    empty = analyze_download(b"", "empty.bin")
    assert empty.detected_type == "empty"
