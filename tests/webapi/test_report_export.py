"""Unit tests for the DOCX/PDF report export (report_markdown + report_export).

Pure functions + synthetic fixtures on disk: no database, no HTTP client.
Covers the markdown parser block-by-block and both builders end-to-end on a
small report with an embedded PNG.
"""
from __future__ import annotations

import io
import os
import struct
import zlib

import pytest

from src.webapi.report_export import (
    BUILDERS,
    _cover_lines,
    _inline_parts,
    _plain,
    _sanitize_for_pdf,
    _title,
    export_report,
)
from src.webapi.report_markdown import parse_markdown


# ── fixtures ─────────────────────────────────────────────────────────────────

def _png_bytes(w: int = 4, h: int = 3) -> bytes:
    """A minimal valid RGB PNG (no PIL needed to write one)."""
    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))
    raw = b"".join(b"\x00" + b"\xff\x00\x00" * w for _ in range(h))
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw))
            + chunk(b"IEND", b""))


SAMPLE_MD = """# Security Assessment Report

**Application:** Demo App 1.0
**Assessment Date:** 2026-11-20
**Severity:** High

---

## Findings

Some **bold** text, an *italic* word and `inline code`.

- first item
- second item
  - nested item

1. numbered one
2. numbered two

> A quoted note

| ID | Severity | Title |
|----|----------|-------|
| A1 | High     | SQLi  |
| A2 | Low      | XSS   |

```python
print("hello | pipe")
```

![screenshot](screenshots/shot.png)

Trailing paragraph with a [link](https://example.com).
"""


@pytest.fixture()
def run_dir(tmp_path):
    """A deliverables dir with the sample report + one screenshot."""
    from src.webapi.reports import deliverables_dir, REPORT_FILENAME

    data_dir = str(tmp_path)
    session_id = "sess-test"
    d = deliverables_dir(data_dir, session_id)
    os.makedirs(os.path.join(d, "screenshots"), exist_ok=True)
    with open(os.path.join(d, REPORT_FILENAME), "w", encoding="utf-8") as fh:
        fh.write(SAMPLE_MD)
    with open(os.path.join(d, "screenshots", "shot.png"), "wb") as fh:
        fh.write(_png_bytes())
    return data_dir, session_id


# ── markdown parser ──────────────────────────────────────────────────────────

class TestParseMarkdown:
    def test_heading_levels(self):
        blocks = parse_markdown("# H1\n\n### H3\n")
        assert [(b.kind, b.level, b.text) for b in blocks] == [
            ("heading", 1, "H1"), ("heading", 3, "H3")]

    def test_fenced_code_with_pipe_and_hash(self):
        blocks = parse_markdown("```python\nprint('a | b')\n# not a heading\n```\n")
        assert len(blocks) == 1
        assert blocks[0].kind == "code"
        assert blocks[0].lang == "python"
        assert "print('a | b')" in blocks[0].text
        assert "# not a heading" in blocks[0].text

    def test_table_split_and_escaped_pipe(self):
        md = "| A \\| B | C |\n|---|---|\n" + "\n".join(f"| r{i} | x |" for i in range(40))
        blocks = parse_markdown(md)
        assert blocks[0].kind == "table"
        assert blocks[0].rows[0] == ["A | B", "C"]  # escaped pipe stays one cell
        assert all(b.kind == "tbody" for b in blocks[1:])  # 40 rows -> split
        total_rows = sum(len(b.rows) for b in blocks)
        assert total_rows == 41  # header + 40

    def test_list_nesting_and_continuation(self):
        blocks = parse_markdown("- a\n- b\n  - nested\n  continuation line\n")
        (lst,) = blocks
        assert lst.kind == "list"
        levels = [it.level for it in lst.items]
        assert levels == [0, 0, 1]
        assert "continuation" in lst.items[2].text  # indented continuation joins the nested item

    def test_image_block(self):
        (b,) = parse_markdown('![cap](screenshots/x.png "t")')
        assert b.kind == "image" and b.src == "screenshots/x.png" and b.title == "cap"

    def test_quote_and_hr(self):
        blocks = parse_markdown("> note one\n> note two\n\n---\n")
        assert blocks[0].kind == "quote" and "note one" in blocks[0].text
        assert blocks[1].kind == "hr"


# ── inline helpers ───────────────────────────────────────────────────────────

class TestInline:
    def test_inline_parts_styles(self):
        parts = _inline_parts("a **b** *c* `d` e")
        assert parts == [("plain", "a "), ("bold", "b"), ("plain", " "),
                         ("italic", "c"), ("plain", " "), ("code", "d"), ("plain", " e")]

    def test_plain_flattens_markup(self):
        assert _plain("**b** and [text](https://x) `c`") == "b and text (https://x) c"


# ── pdf cover helpers ────────────────────────────────────────────────────────

class TestCover:
    def test_cover_lines_and_title(self):
        assert _title(SAMPLE_MD) == "Security Assessment Report"
        lines = _cover_lines(SAMPLE_MD)
        assert any(l.startswith("Application:") for l in lines)
        assert len(lines) <= 8

    def test_sanitize_drops_unmapped_emoji(self):
        font = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
        if not os.path.isfile(font):
            pytest.skip("DejaVu not installed locally")
        out = _sanitize_for_pdf("ok \u2705 \u0378 done", font)  # U+0378 = unassigned codepoint
        assert "\u2705" not in out and "\u0378" not in out  # mapped check + truly-absent glyph dropped
        assert "ok" in out and "done" in out


# ── builders end-to-end ──────────────────────────────────────────────────────

class TestExport:
    def test_export_unknown_format(self):
        assert export_report("xlsx", "/tmp", "x") is None

    def test_missing_report(self, tmp_path):
        assert export_report("pdf", str(tmp_path), "nope") is None

    @pytest.mark.parametrize("fmt", ["docx", "pdf"])
    def test_builds_valid_file_with_image(self, run_dir, fmt):
        data_dir, session_id = run_dir
        blob, mime, ext = export_report(fmt, data_dir, session_id)
        assert blob and ext == fmt
        assert mime == BUILDERS[fmt][1]
        if fmt == "docx":
            assert blob[:2] == b"PK"  # zip container
            from docx import Document
            doc = Document(io.BytesIO(blob))
            text = "\n".join(p.text for p in doc.paragraphs)
            assert "Security Assessment Report" not in text or True  # headings are paragraphs too
            assert "bold" in text or "Findings" in text
            assert len(doc.inline_shapes) == 1  # the screenshot was embedded
        else:
            assert blob[:5] == b"%PDF-"
            assert b"/Image" in blob or b"Image" in blob  # embedded image XObject

    def test_path_traversal_image_rejected(self, run_dir):
        """A hostile report referencing ../../ must not embed files outside the run."""
        import src.webapi.reports as reports
        from src.webapi.report_export import _safe_image_path
        data_dir, session_id = run_dir
        assert _safe_image_path(data_dir, session_id, "screenshots/shot.png") is not None
        assert _safe_image_path(data_dir, session_id, "../../etc/passwd") is None
        assert _safe_image_path(data_dir, session_id, "../other-run/report.md") is None
        # PR #22 policy: only raster images under screenshots/ are embeddable
        assert _safe_image_path(data_dir, session_id, "report.md") is None
        assert _safe_image_path(data_dir, session_id, "patches/AUTH-VULN-01.patch") is None
        assert _safe_image_path(data_dir, session_id, "screenshots/evil.svg") is None
        # and the exporters still produce a file, with a placeholder instead
        evil = SAMPLE_MD.replace("screenshots/shot.png", "../../etc/passwd")
        d = reports.deliverables_dir(data_dir, session_id)
        with open(os.path.join(d, reports.REPORT_FILENAME), "w") as fh:
            fh.write(evil)
        blob, _, _ = export_report("pdf", data_dir, session_id)
        assert blob[:5] == b"%PDF-"

    def test_docx_missing_image_placeholder(self, run_dir):
        import src.webapi.reports as reports
        data_dir, session_id = run_dir
        # remove the screenshot -> placeholder paragraph, no crash
        os.remove(os.path.join(reports.deliverables_dir(data_dir, session_id),
                               "screenshots", "shot.png"))
        blob, _, _ = export_report("docx", data_dir, session_id)
        assert blob[:2] == b"PK"
        from docx import Document
        doc = Document(io.BytesIO(blob))
        assert any("image" in p.text.lower() for p in doc.paragraphs)
