from netsniffer.payload import (
    describe_payload, hex_preview, hexdump, is_mostly_text, printable_preview, redact_sensitive,
)
from netsniffer.protocols import describe_tls, looks_like_http, looks_like_tls


def test_printable_text_passes_through():
    assert printable_preview(b"hello world") == "hello world"


def test_control_characters_are_neutralised():
    # ESC (0x1b) starts terminal escape sequences - it must never reach the terminal.
    out = printable_preview(b"a\x1b[31mred\x00b")
    assert "\x1b" not in out and "\x00" not in out
    assert out == "a.[31mred.b"


def test_crlf_shown_as_visible_escapes():
    assert printable_preview(b"GET / HTTP/1.1\r\nHost: x\r\n") == "GET / HTTP/1.1\\r\\nHost: x\\r\\n"


def test_truncation_reports_hidden_bytes():
    out = printable_preview(b"A" * 100, max_bytes=10)
    assert out.startswith("A" * 10) and "(+90 more bytes)" in out


def test_high_bytes_never_raise():
    printable_preview(bytes(range(256)))     # must not raise


def test_redaction_of_headers():
    text = "GET / HTTP/1.1\r\nAuthorization: Bearer abc123\r\nCookie: sid=zzz\r\nHost: a\r\n"
    out = redact_sensitive(text)
    assert "abc123" not in out and "zzz" not in out
    assert "Host: a" in out
    assert "Authorization: [REDACTED]" in out


def test_redaction_of_form_fields():
    out = redact_sensitive("user=bob&password=s3cret&token=abc")
    assert "s3cret" not in out and "abc" not in out
    assert "user=bob" in out


def test_redaction_applies_inside_preview():
    assert "s3cret" not in printable_preview(b"password=s3cret")


def test_text_vs_binary_detection():
    assert is_mostly_text(b"plain readable text\r\n")
    assert not is_mostly_text(bytes(range(128, 200)))
    assert not is_mostly_text(b"")


def test_describe_payload_kinds():
    assert describe_payload(b"hello")[0] == "text"
    kind, text = describe_payload(bytes([0x16, 0x03, 0x01, 0x99, 0xfe, 0xfd, 0x80] * 10))
    assert kind == "binary" and text.startswith("16 03 01")


def test_hex_helpers():
    assert hex_preview(b"\x01\x02\x03", 2) == "01 02 ..."
    dump = hexdump(b"ABC\x00")
    assert dump.startswith("0000  41 42 43 00") and dump.endswith("|ABC.|")


def test_http_signatures():
    assert looks_like_http(b"GET / HTTP/1.1")
    assert looks_like_http(b"HTTP/1.1 404 Not Found")
    assert not looks_like_http(b"\x16\x03\x01")
    assert not looks_like_http(b"GETTING")


def test_tls_signatures():
    assert looks_like_tls(bytes([22, 3, 3, 0, 10]))
    assert not looks_like_tls(bytes([22, 3, 3]))            # too short
    assert not looks_like_tls(bytes([99, 3, 3, 0, 10]))     # unknown record type
    assert not looks_like_tls(bytes([22, 9, 9, 0, 10]))     # bad version
    assert describe_tls(bytes([23, 3, 3, 0, 4, 0, 0, 0, 0])) == "TLS Application Data"
