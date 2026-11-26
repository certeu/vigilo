"""Export a run's deliverables report to DOCX and PDF.

The report is a Markdown document written by the report agent, referencing its
evidence screenshots relatively (``screenshots/x.png``). Both exporters run on the
same block list from :mod:`src.webapi.report_markdown`, so the text and the
embedded images are identical in the two formats.

Pure Python on purpose: no pandoc, no LibreOffice, no native build — the API image
is ``python:3.13-slim`` and rebuilding it on the Raspberry Pi is out of the
question. ``python-docx`` writes the DOCX; ``fpdf2`` (bundles harfbuzz, subsets
fonts itself) lays out the PDF with the DejaVu TTF shipped in the API image.
"""
from __future__ import annotations

import io
import logging
import os
import re

from src.webapi.reports import REPORT_FILENAME, deliverables_dir, open_report_image

log = logging.getLogger(__name__)

DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
PDF_MIME = "application/pdf"

# DejaVu Sans: full Latin coverage, subfamily TTFs (Debian splits Bold/Oblique out).
_DEJAVU_DIRS = (
    "/usr/share/fonts/truetype/dejavu",
    "/usr/share/fonts/dejavu",
)


def _report_text(data_dir: str, session_id: str) -> str | None:
    path = os.path.join(deliverables_dir(data_dir, session_id), REPORT_FILENAME)
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


# Report agents emit emoji that DejaVu Sans does not carry; fpdf2 then drops the
# character SILENTLY (only a log line), which made ✅/❌ vanish from the PDF.
# Map the known ones to the closest glyph DejaVu actually has.
_PDF_GLYPH_FALLBACKS = {
    "\ufe0f": "",        # variation selector: no glyph, invisible anyway
    "\u2705": "\u2714",  # ✅ -> ✔ heavy check mark
    "\u274c": "\u2718",  # ❌ -> ✘ heavy ballot X
    "\u2716": "\u2718",  # heavy multiplication x -> ✘
    "\u2717": "\u2718",  # ballot x -> ✘
    "\u2b24": "\u2714",  # heavy check mark circle -> ✔
    "\u2b25": "\u2718",  # heavy ballot x circle -> ✘
    "\u2757": "\u203c",  # heavy exclamation mark -> ‼
    "\u2753": "?",       # black question mark -> plain ?
}

_cmap_cache: dict[str, set[int]] = {}


def _font_cmap(path: str) -> set[int]:
    """Codepoints the font actually draws (cached per path)."""
    if path not in _cmap_cache:
        from fontTools.ttLib import TTFont

        with TTFont(path, lazy=True) as font:
            _cmap_cache[path] = set(font.getBestCmap().keys())
    return _cmap_cache[path]


def _sanitize_for_pdf(text: str, font_path: str) -> str:
    """Swap emoji for DejaVu-present glyphs; drop the rest loudly.

    Applied to the whole markdown before parsing so headings, tables, the cover
    and captions all get the same treatment. Anything still unmappable is
    removed with a warning listing the codepoints — a silently missing glyph is
    what this function exists to prevent.
    """
    for src, dst in _PDF_GLYPH_FALLBACKS.items():
        text = text.replace(src, dst)
    cmap = _font_cmap(font_path)
    dropped = sorted({ch for ch in text if ord(ch) > 127 and ord(ch) not in cmap})
    if dropped:
        log.warning(
            "PDF export: dropping %d character(s) absent from DejaVu: %s",
            len(dropped), " ".join(f"U+{ord(ch):04X}" for ch in dropped),
        )
        text = "".join(ch for ch in text if ord(ch) <= 127 or ord(ch) in cmap)
    return text


def _is_image(path: str) -> bool:
    return os.path.isfile(path) and os.path.getsize(path) > 0


def _safe_image_path(data_dir: str, session_id: str, src: str) -> str | None:
    """Resolve a report-relative image to a local path for embedding, reusing the
    same policy as PR #22's ``/files/`` endpoint: only raster images under
    ``deliverables/screenshots/``, opened through safefs (O_NOFOLLOW) so a symlink
    planted in the agent-controlled workspace cannot leak files from outside the
    run, and ``../../`` traversal is rejected by construction.

    Returns a path only when the file passes :func:`open_report_image`; the caller
    must still handle a vanished file between check and open.
    """
    if open_report_image(data_dir, session_id, src) is None:
        return None
    parts = tuple(p for p in src.replace("\\", "/").split("/") if p not in ("", "."))
    return os.path.join(deliverables_dir(data_dir, session_id), *parts)


# ── shared inline handling ───────────────────────────────────────────────────
_INLINE_TOKEN = re.compile(r"(\*\*[^*\n]+\*\*|(?<!\*)\*[^*\n]+\*(?!\*)|`[^`\n]+`)")
_LINK = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")


def _inline_parts(text: str) -> list[tuple[str, str]]:
    """Split inline markdown into ``(style, text)`` parts.

    style ∈ ``bold`` | ``italic`` | ``code`` | ``plain``. Word runs are built from
    these; the PDF flattens them with :func:`_plain`.
    """
    parts: list[tuple[str, str]] = []
    for piece in _INLINE_TOKEN.split(text):
        if not piece:
            continue
        if piece.startswith("**") and piece.endswith("**") and len(piece) > 4:
            parts.append(("bold", piece[2:-2]))
        elif piece.startswith("`") and piece.endswith("`") and len(piece) > 2:
            parts.append(("code", piece[1:-1]))
        elif piece.startswith("*") and piece.endswith("*") and len(piece) > 2:
            parts.append(("italic", piece[1:-1]))
        else:
            parts.append(("plain", piece))
    return parts


def _plain(text: str) -> str:
    """Flatten inline markdown for engines that do not style it themselves."""
    text = _LINK.sub(lambda m: f"{m.group(1)} ({m.group(2)})", text)
    text = re.sub(r"\*\*([^*\n]+)\*\*", r"\1", text)
    text = re.sub(r"(?<!\*)\*([^*\n]+)\*(?!\*)", r"\1", text)
    text = text.replace("`", "")
    text = text.replace("<br>", "\n").replace("<br/>", "\n").replace("\\|", "|")
    return text


# ── DOCX ─────────────────────────────────────────────────────────────────────
def _shade_paragraph(paragraph, fill: str) -> None:
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    p_pr = paragraph._p.get_or_add_pPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    p_pr.append(shd)


def _shade_cell(cell, fill: str) -> None:
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn

    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    tc_pr.append(shd)


def _docx_rich(paragraph, text: str, size_pt: float) -> None:
    from docx.shared import Pt, RGBColor

    for style, chunk in _inline_parts(_LINK.sub(lambda m: m.group(1), text)):
        run = paragraph.add_run(chunk)
        run.font.size = Pt(size_pt)
        if style == "bold":
            run.bold = True
        elif style == "italic":
            run.italic = True
        elif style == "code":
            run.font.name = "Consolas"
            run.font.color.rgb = RGBColor(0xA3, 0x1C, 0x1C)


def _docx_code(doc, text: str) -> None:
    from docx.shared import Pt, RGBColor

    for chunk in (text.split("\n") or [""]):
        p = doc.add_paragraph()
        pf = p.paragraph_format
        pf.space_before = Pt(0)
        pf.space_after = Pt(0)
        pf.left_indent = Pt(10)
        run = p.add_run(chunk if chunk else " ")
        run.font.name = "Consolas"
        run.font.size = Pt(8)
        run.font.color.rgb = RGBColor(0x24, 0x29, 0x2E)
        _shade_paragraph(p, "F4F5F7")
    doc.add_paragraph().paragraph_format.space_after = Pt(4)


def _docx_table(doc, rows: list[list[str]], header: bool = True) -> None:
    """Markdown pipe table -> Word table. ``header=False`` continues a table
    split across pages (the repeated header is already printed)."""
    from docx.shared import Pt

    if not rows:
        return
    ncols = max(len(r) for r in rows)
    table = doc.add_table(rows=0, cols=ncols)
    table.style = "Table Grid"
    for ri, row in enumerate(rows):
        cells = table.add_row().cells
        is_head = header and ri == 0
        for ci in range(ncols):
            raw = row[ci] if ci < len(row) else ""
            cell = cells[ci]
            para = cell.paragraphs[0]
            _docx_rich(para, raw, 8)
            if is_head:
                for run in para.runs:
                    run.bold = True
                _shade_cell(cell, "ECEEF2")
    doc.add_paragraph().paragraph_format.space_after = Pt(4)


def build_report_docx(data_dir: str, session_id: str) -> bytes | None:
    """Render the report markdown to a .docx with the evidence screenshots embedded."""
    text = _report_text(data_dir, session_id)
    if text is None:
        return None

    from docx import Document
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.shared import Inches, Pt, RGBColor

    from src.webapi.report_markdown import parse_markdown

    base_dir = deliverables_dir(data_dir, session_id)
    doc = Document()
    section = doc.sections[0]
    section.left_margin = Inches(0.75)
    section.right_margin = Inches(0.75)
    section.top_margin = Inches(0.7)
    section.bottom_margin = Inches(0.7)
    usable = section.page_width - section.left_margin - section.right_margin

    doc.styles["Normal"].font.name = "Calibri"
    doc.styles["Normal"].font.size = Pt(9.5)

    for block in parse_markdown(text):
        if block.kind == "heading":
            level = min(block.level, 4)
            para = doc.add_heading(level=level)
            run = para.add_run(_plain(block.text))
            run.font.size = Pt({1: 20, 2: 15, 3: 12.5, 4: 11.5}[level])
            run.font.name = "Calibri"
            if level <= 2:
                run.font.color.rgb = RGBColor(0x1F, 0x2A, 0x44)
        elif block.kind == "para":
            para = doc.add_paragraph()
            _docx_rich(para, block.text, 9.5)
            para.paragraph_format.space_after = Pt(6)
        elif block.kind == "code":
            _docx_code(doc, block.text)
        elif block.kind == "table":
            _docx_table(doc, block.rows)
        elif block.kind == "list":
            for item in block.items:
                style = "List Bullet" if item.level == 0 else "List Bullet 2"
                para = doc.add_paragraph(style=style)
                _docx_rich(para, item.text, 9.5)
                para.paragraph_format.space_after = Pt(1)
        elif block.kind == "tbody":
            _docx_table(doc, block.rows, header=False)
        elif block.kind == "quote":
            para = doc.add_paragraph()
            run = para.add_run(_plain(block.text))
            run.italic = True
            run.font.size = Pt(9)
            run.font.color.rgb = RGBColor(0x55, 0x5A, 0x60)
        elif block.kind == "hr":
            doc.add_paragraph().paragraph_format.space_after = Pt(2)
        elif block.kind == "image":
            target = _safe_image_path(data_dir, session_id, block.src)
            if target is None or not _is_image(target):
                para = doc.add_paragraph()
                run = para.add_run(f"[image manquante : {block.src}]")
                run.italic = True
                run.font.size = Pt(8)
                run.font.color.rgb = RGBColor(0x80, 0x80, 0x80)
                continue
            try:
                para = doc.add_paragraph()
                para.alignment = WD_ALIGN_PARAGRAPH.CENTER
                # Width only (no Height): python-docx keeps the DPI-exact ratio.
                para.add_run().add_picture(target, width=min(usable, Inches(6.6)))
                if block.title:
                    cap = doc.add_paragraph()
                    cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
                    crun = cap.add_run(f"Figure — {block.title}")
                    crun.italic = True
                    crun.font.size = Pt(8)
                    crun.font.color.rgb = RGBColor(0x55, 0x5A, 0x60)
            except Exception:  # noqa: BLE001 — one unreadable image must not kill the export
                doc.add_paragraph(f"[image illisible : {block.src}]")

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


# ── PDF ──────────────────────────────────────────────────────────────────────
def _find_fonts() -> tuple[str, str, str, str] | None:
    """Return (regular, bold, italic, mono) DejaVu paths, or None when absent."""
    for d in _DEJAVU_DIRS:
        cand = (
            os.path.join(d, "DejaVuSans.ttf"),
            os.path.join(d, "DejaVuSans-Bold.ttf"),
            # Debian splits the Oblique face into fonts-dejavu-core only when
            # fonts-dejavu-extra is installed; fall back to the regular file
            # (fpdf then renders italic text with upright glyphs, not a crash).
            os.path.join(d, "DejaVuSans-Oblique.ttf"),
            os.path.join(d, "DejaVuSansMono.ttf"),
        )
        reg = cand[0]
        if not (os.path.isfile(reg) and os.path.isfile(cand[1]) and os.path.isfile(cand[3])):
            continue
        italic = cand[2] if os.path.isfile(cand[2]) else reg
        return (reg, cand[1], italic, cand[3])
    return None


_SEV_COLOR = (0xB0, 0x1C, 0x1C)
_TITLE_COLOR = (0x1F, 0x2A, 0x44)
_BODY_COLOR = (0x22, 0x26, 0x2A)


def _cover_lines(text: str, max_lines: int = 8) -> list[str]:
    """The leading ``**Key:** value`` block of the report = cover metadata."""
    out: list[str] = []
    for line in text.splitlines()[1:]:
        s = line.strip()
        if not s or s in ("---", "***", "___"):
            if out:
                break
            continue
        if s.startswith("**") and ":**" in s:
            out.append(s.replace("**", ""))
        elif out:
            break
        if len(out) >= max_lines:
            break
    return out


def _title(text: str) -> str:
    for line in text.splitlines():
        if line.startswith("# "):
            return _plain(line[2:].strip())
    return "Security Assessment Report"


def _cover_page(pdf, text: str) -> None:
    pdf.add_page()
    pdf.set_font("DejaVu", "B", 21)
    pdf.set_text_color(*_TITLE_COLOR)
    pdf.multi_cell(0, 10.5, _title(text), align="L", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)
    pdf.set_text_color(0x33, 0x38, 0x3D)
    for line in _cover_lines(text):
        label, _, value = line.partition(":")
        pdf.set_font("DejaVu", "B", 9)
        pdf.cell(pdf.get_string_width(label + ": ") + 2, 5.4, label + ":")
        pdf.set_font("DejaVu", "", 9)
        # fpdf2 leaves x at the right margin after multi_cell; without the reset
        # the next label starts off-page ("Not enough horizontal space").
        pdf.multi_cell(0, 5.4, _plain(value.strip()), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)
    pdf.set_draw_color(*_SEV_COLOR)
    pdf.set_line_width(0.8)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.set_text_color(*_BODY_COLOR)


def _skip_cover(blocks, text: str):
    """Drop the H1 + the metadata paragraphs already printed on the cover page."""
    cover_keys = [c.split(":", 1)[0].strip() for c in _cover_lines(text)]
    out = []
    title_done = False
    for block in blocks:
        if not title_done:
            if block.kind == "heading" and block.level == 1:
                title_done = True
                continue
            continue
        if block.kind == "hr":
            continue
        if block.kind == "para" and any(_plain(block.text).startswith(k) for k in cover_keys):
            continue
        out.append(block)
    return out


def _pdf_code(pdf, text: str, content_w: float) -> None:
    """Shaded, monospaced, non-wrapping code frame.

    Lines are hard-wrapped to the frame width *before* being drawn (``cell``
    does not wrap), measured with the mono font actually in use so a wrapped
    continuation never overruns the box edge.
    """
    fs = 7.2
    line_h = 3.55
    pdf.set_font("DejaVuMono", "", fs)
    inner_w = content_w - 5
    char_w = pdf.get_string_width("M") or 1.5
    max_chars = max(20, int(inner_w / char_w))

    lines: list[str] = []
    for raw in text.replace("\t", "    ").split("\n"):
        line = raw.expandtabs(4)
        while line and pdf.get_string_width(line) > inner_w:
            cut = max_chars
            while cut > 8 and pdf.get_string_width(line[:cut]) > inner_w:
                cut -= 1
            lines.append(line[:cut])
            line = "  " + line[cut:].lstrip()
        lines.append(line)
    if not lines:
        return
    max_frame = pdf.h - pdf.t_margin - pdf.b_margin - 10
    per_frame = max(6, int(max_frame / line_h))
    pdf.set_line_width(0.2)
    for start in range(0, len(lines), per_frame):
        chunk = lines[start:start + per_frame]
        needed = len(chunk) * line_h + 4
        if pdf.get_y() + needed > pdf.h - pdf.b_margin:
            pdf.add_page()
        y0 = pdf.get_y()
        pdf.set_fill_color(0xF4, 0xF5, 0xF7)
        pdf.set_draw_color(0xE1, 0xE4, 0xE8)
        pdf.rect(pdf.l_margin, y0, content_w, needed, style="DF")
        pdf.set_text_color(0x24, 0x29, 0x2E)
        pdf.set_font("DejaVuMono", "", fs)
        pdf.set_y(y0 + 2)
        for ln in chunk:
            # cell() advances the cursor; without resetting x each line is drawn
            # where the previous one stopped (and laid out as its suffix).
            pdf.set_x(pdf.l_margin + 2.5)
            pdf.cell(inner_w, line_h, ln, new_x="LMARGIN", new_y="NEXT")
        pdf.set_y(y0 + needed + 2)
    pdf.set_text_color(*_BODY_COLOR)
    pdf.ln(1.2)


def _col_weight(header: str, ci: int, all_cells: list[str]) -> float:
    """Relative column width: headers are short labels, bodies carry the text."""
    import statistics

    body = [c for c in all_cells if c]
    med = statistics.median(len(c) for c in body) if body else 3
    h = len(header)
    if ci == 0 or (h <= 3 and med <= 6):
        return 1.0  # "#", severity, short status flags
    if med <= 12:
        return max(1.4, med / 5.0)
    return min(4.0, 1.2 + med / 14.0)


def _pdf_table(pdf, rows: list[list[str]], content_w: float, header: bool = True) -> None:
    if not rows:
        return
    ncols = max(len(r) for r in rows)
    plain = [[_plain(r[ci]) if ci < len(r) else "" for ci in range(ncols)] for r in rows]
    header = plain[0] if header else [""] * ncols
    all_cells = [c for row in plain[1:] for c in row]
    weights = [_col_weight(header[ci], ci, all_cells) for ci in range(ncols)]
    total = sum(weights)
    widths = [content_w * w / total for w in weights]

    line_h = 3.3
    fs = 6.8
    pdf.set_font("DejaVu", "", fs)

    def cell_lines(text: str, width_mm: float) -> int:
        """Real wrapped-line count via fpdf's dry run (no output, no side effect)."""
        if not text:
            return 1
        try:
            lines = pdf.multi_cell(
                width_mm,
                line_h,
                text,
                align="L",
                border=0,
                dry_run=True,
                output="LINES",
            )
        except Exception:  # noqa: BLE001
            return max(1, len(text) // max(int(width_mm / 1.5), 6) + 1)
        return max(1, len(lines))

    for ri, cells in enumerate(plain):
        is_head = header and ri == 0
        pdf.set_font("DejaVu", "B" if is_head else "", fs)
        nlines = max(cell_lines(cell, widths[ci] - 2.2) for ci, cell in enumerate(cells))
        row_h = min(nlines, 16) * line_h + 1.4

        if pdf.get_y() + row_h > pdf.h - pdf.b_margin:
            pdf.add_page()
            pdf.set_font("DejaVu", "B" if is_head else "", fs)
        y = pdf.get_y()
        x = pdf.l_margin
        pdf.set_draw_color(0xD6, 0xDA, 0xDF)
        pdf.set_line_width(0.15)
        for ci, cell in enumerate(cells):
            pdf.set_fill_color(0xEC, 0xEF, 0xF3) if is_head else pdf.set_fill_color(255, 255, 255)
            pdf.rect(x, y, widths[ci], row_h, style="DF")
            pdf.set_xy(x + 1.1, y + 0.7)
            pdf.multi_cell(
                widths[ci] - 2.2,
                line_h,
                cell,
                align="L",
                border=0,
                max_line_height=line_h,
            )
            x += widths[ci]
        pdf.set_y(y + row_h)
    pdf.set_text_color(*_BODY_COLOR)
    pdf.ln(2.2)


def _pdf_image(pdf, path: str | None, block, content_w: float) -> None:
    from PIL import Image

    if not path or not _is_image(path):
        pdf.set_font("DejaVu", "I", 8)
        pdf.set_text_color(0x80, 0x80, 0x80)
        pdf.multi_cell(content_w, 4.4, f"[image manquante : {block.src}]")
        pdf.set_text_color(*_BODY_COLOR)
        return
    try:
        with Image.open(path) as im:
            w_px, h_px = im.size
            fmt = (im.format or "").upper()
    except Exception:  # noqa: BLE001
        pdf.set_font("DejaVu", "I", 8)
        pdf.multi_cell(content_w, 4.4, f"[image illisible : {block.src}]")
        return
    if not w_px or not h_px:
        return
    max_w = content_w * 0.92
    max_h = pdf.h - pdf.t_margin - pdf.b_margin - 24  # leave room for the caption
    scale = min(max_w / w_px, max_h / h_px)
    w_mm, h_mm = w_px * scale, h_px * scale
    if pdf.get_y() + h_mm + 10 > pdf.h - pdf.b_margin:
        pdf.add_page()
    y = pdf.get_y()
    x = pdf.l_margin + (content_w - w_mm) / 2
    pdf.set_draw_color(0xC8, 0xCD, 0xD2)
    pdf.set_line_width(0.2)
    pdf.rect(x, y, w_mm, h_mm)
    try:
        # Lossless PNG stays PNG (crisp screenshots); JPEG is auto-detected.
        pdf.image(path, x=x, y=y, w=w_mm, h=h_mm)  # format auto-détecté par fpdf2
    except Exception:  # noqa: BLE001
        pdf.set_font("DejaVu", "I", 8)
        pdf.multi_cell(content_w, 4.4, f"[image could not be embedded: {block.src}]")
        return
    pdf.set_y(y + h_mm + 1.2)
    if block.title:
        pdf.set_font("DejaVu", "I", 7.8)
        pdf.set_text_color(0x55, 0x5A, 0x60)
        pdf.multi_cell(content_w, 4, f"Figure — {_plain(block.title)}", align="C")
        pdf.set_text_color(*_BODY_COLOR)
    pdf.ln(2.4)


def build_report_pdf(data_dir: str, session_id: str) -> bytes | None:
    """Render the report markdown to a .pdf with the evidence screenshots embedded."""
    text = _report_text(data_dir, session_id)
    if text is None:
        return None

    from fpdf import FPDF

    from src.webapi.report_markdown import parse_markdown

    base_dir = deliverables_dir(data_dir, session_id)
    fonts = _find_fonts()
    if fonts is None:
        raise RuntimeError("DejaVu fonts absent from the API image (see deploy/Dockerfile.api)")
    reg, bold, italic, mono = fonts
    text = _sanitize_for_pdf(text, reg)

    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_margins(16, 14, 16)
    pdf.add_font("DejaVu", "", reg)
    pdf.add_font("DejaVu", "B", bold)
    pdf.add_font("DejaVu", "I", italic)
    pdf.add_font("DejaVuMono", "", mono)
    _cover_page(pdf, text)

    content_w = pdf.w - pdf.l_margin - pdf.r_margin
    sizes = {1: 17, 2: 13.5, 3: 11.5, 4: 10.5}

    for block in _skip_cover(parse_markdown(text), text):
        if block.kind == "heading":
            level = min(block.level, 4)
            if pdf.get_y() > pdf.h - 45:
                pdf.add_page()
            pdf.ln(2)
            pdf.set_font("DejaVu", "B", sizes[level])
            pdf.set_text_color(*(_SEV_COLOR if level == 2 else _TITLE_COLOR))
            pdf.multi_cell(content_w, 6.2, _plain(block.text), align="L")
            pdf.set_text_color(*_BODY_COLOR)
            pdf.ln(1)
        elif block.kind == "para":
            pdf.set_font("DejaVu", "", 9.3)
            pdf.set_text_color(*_BODY_COLOR)
            pdf.multi_cell(content_w, 4.7, _plain(block.text), align="L")
            pdf.ln(1.3)
        elif block.kind == "list":
            pdf.set_font("DejaVu", "", 9.3)
            for item in block.items:
                indent = 4 + 4 * min(item.level, 3)
                pdf.set_x(pdf.l_margin + indent)
                bullet = "•" if item.level == 0 else "–"
                pdf.multi_cell(content_w - indent, 4.6, f"{bullet} {_plain(item.text)}", align="L")
            pdf.ln(1.3)
        elif block.kind == "code":
            _pdf_code(pdf, block.text, content_w)
        elif block.kind == "table":
            _pdf_table(pdf, block.rows, content_w)
        elif block.kind == "tbody":
            _pdf_table(pdf, block.rows, content_w, header=False)
        elif block.kind == "image":
            target = _safe_image_path(data_dir, session_id, block.src)
            _pdf_image(pdf, target if target else os.path.join(base_dir, block.src), block, content_w)
        elif block.kind == "quote":
            pdf.set_font("DejaVu", "I", 9)
            pdf.set_text_color(0x55, 0x5A, 0x60)
            pdf.set_x(pdf.l_margin + 3)
            pdf.multi_cell(content_w - 3, 4.6, _plain(block.text), align="L")
            pdf.set_text_color(*_BODY_COLOR)
            pdf.ln(1.3)
        elif block.kind == "hr":
            pdf.ln(2)
            pdf.set_draw_color(0xD0, 0xD4, 0xD8)
            pdf.set_line_width(0.3)
            pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
            pdf.ln(3)

    return bytes(pdf.output())


BUILDERS = {
    "docx": (build_report_docx, DOCX_MIME, "docx"),
    "pdf": (build_report_pdf, PDF_MIME, "pdf"),
}


def export_report(export: str, data_dir: str, session_id: str) -> tuple[bytes, str, str] | None:
    """Return ``(bytes, media_type, extension)`` for ``docx``/``pdf``, else None."""
    entry = BUILDERS.get(export)
    if entry is None:
        return None
    builder, media_type, ext = entry
    blob = builder(data_dir, session_id)
    if not blob:
        return None
    return blob, media_type, ext
