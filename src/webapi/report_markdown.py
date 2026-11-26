"""Minimal, dependency-free Markdown block parser for report export.

Vigilo reports are written by an LLM agent, so the flavour is GFM-ish but not
strict: ATX headings, fenced code (```` ``` ````/```` ~~~ ````), pipe tables,
bullet/numbered lists, block quotes, ``---`` rules, ``![alt](path)`` images and
paragraphs. That is all this parser recognises; everything else (HTML tags,
setext headings, footnotes) is kept as literal paragraph text, which is exactly
what the report generator never emits. Tables and code fences are parsed before
anything else so ``|`` inside a code block, or a ``#`` inside a fenced block,
does not get mistaken for a table/heading.

Both exporters (DOCX and PDF) consume the same block list, so the two documents
can never drift in structure.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})\s*([\w+-]*)\s*$")
_BULLET = re.compile(r"^(\s*)([-*+]|\d{1,2}[.)])\s+(.*)$")
_IMAGE = re.compile(r"^!\[([^\]]*)\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)$")
_HR = re.compile(r"^\s{0,3}([-*_])(?:\s*\1){2,}\s*$")
_TABLE_SEP = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?\s*$")


@dataclass
class Block:
    kind: str  # heading|para|code|table|list|quote|image|hr
    text: str = ""
    level: int = 0
    items: list["ListItem"] = field(default_factory=list)
    rows: list[list[str]] = field(default_factory=list)
    src: str = ""
    title: str = ""
    lang: str = ""


@dataclass
class ListItem:
    text: str
    level: int = 0


def _split_row(line: str) -> list[str]:
    """Split a pipe-table row, honouring ``\\|`` escapes and code spans."""
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|") and not s.endswith("\\|"):
        s = s[:-1]
    cells: list[str] = []
    buf = ""
    in_code = False
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "\\" and i + 1 < len(s) and s[i + 1] == "|":
            buf += "|"
            i += 2
            continue
        if ch == "`":
            in_code = not in_code
            buf += ch
            i += 1
            continue
        if ch == "|" and not in_code:
            cells.append(buf.strip())
            buf = ""
            i += 1
            continue
        buf += ch
        i += 1
    cells.append(buf.strip())
    return cells


def _table_blocks(rows: list[list[str]], rows_per_page: int = 14) -> list[Block]:
    """Split a table whose rows would overflow one page.

    Rendering engines paginate rows, not whole tables, so a 20-row findings
    table has no single page it fits on. Each group of rows becomes its own
    table (``kind="tbody"`` for the follow-ups, so only the first carries the
    header).
    """
    if len(rows) <= rows_per_page + 1:
        return [Block(kind="table", rows=rows)]
    head, body = rows[0], rows[1:]
    out: list[Block] = []
    for start in range(0, len(body), rows_per_page):
        group = body[start:start + rows_per_page]
        if start == 0:
            out.append(Block(kind="table", rows=[head, *group]))
        else:
            out.append(Block(kind="tbody", rows=group))
    return out


def parse_markdown(md: str) -> list[Block]:
    lines = md.replace("\r\n", "\n").split("\n")
    blocks: list[Block] = []
    i = 0
    para: list[str] = []

    def flush_para() -> None:
        nonlocal para
        if para:
            # One Block per source line: the report's cover metadata is a run of
            # consecutive ``**Key:** value`` lines that must stay separable.
            for raw in para:
                joined = raw.strip()
                if not joined:
                    continue
                img = _IMAGE.match(joined)
                if img:
                    blocks.append(Block(kind="image", src=img.group(2), title=img.group(1)))
                else:
                    blocks.append(Block(kind="para", text=joined))
            para = []

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        fence = _FENCE.match(line)
        if fence:
            flush_para()
            marker = fence.group(1)[0]
            lang = fence.group(2)
            body: list[str] = []
            i += 1
            while i < len(lines) and not re.match(rf"^\s{{0,3}}{re.escape(marker)}{{3,}}\s*$", lines[i]):
                body.append(lines[i])
                i += 1
            i += 1  # closing fence (or EOF)
            blocks.append(Block(kind="code", text="\n".join(body), lang=lang))
            continue

        if not stripped:
            flush_para()
            i += 1
            continue

        img = _IMAGE.match(stripped)
        if img and not para:
            blocks.append(Block(kind="image", src=img.group(2), title=img.group(1)))
            i += 1
            continue

        heading = _HEADING.match(line)
        if heading:
            flush_para()
            blocks.append(Block(kind="heading", level=len(heading.group(1)), text=heading.group(2)))
            i += 1
            continue

        if _HR.match(line) and not para:
            flush_para()
            blocks.append(Block(kind="hr"))
            i += 1
            continue

        # Table: header row + separator row.
        if "|" in line and i + 1 < len(lines) and _TABLE_SEP.match(lines[i + 1]):
            flush_para()
            rows = [_split_row(line)]
            i += 2
            while i < len(lines) and "|" in lines[i] and lines[i].strip():
                rows.append(_split_row(lines[i]))
                i += 1
            blocks.extend(_table_blocks(rows))
            continue

        if stripped.startswith(">"):
            flush_para()
            quote: list[str] = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                quote.append(re.sub(r"^\s*>\s?", "", lines[i]))
                i += 1
            blocks.append(Block(kind="quote", text=" ".join(q.strip() for q in quote if q.strip())))
            continue

        bullet = _BULLET.match(line)
        if bullet:
            flush_para()
            indent = len(bullet.group(1).replace("\t", "    "))
            items: list[ListItem] = [ListItem(text=bullet.group(3).strip(), level=indent // 2)]
            i += 1
            while i < len(lines):
                nxt = lines[i]
                if _FENCE.match(nxt):
                    break  # fenced code ends the list: the parser renders it as a block
                nm = _BULLET.match(nxt)
                if nm:
                    ind = len(nm.group(1).replace("\t", "    "))
                    items.append(ListItem(text=nm.group(3).strip(), level=ind // 2))
                    i += 1
                elif nxt.strip() and nxt.startswith(("  ", "\t")):
                    # Indented continuation: the previous item's text plus any
                    # child lines (often a query string or a payload shape).
                    items[-1].text += " " + nxt.strip()
                    i += 1
                else:
                    break
            blocks.append(Block(kind="list", items=items))
            continue

        img = _IMAGE.match(stripped)
        if img and not para:
            blocks.append(Block(kind="image", src=img.group(2), title=img.group(1)))
            i += 1
            continue

        para.append(line)
        i += 1

    flush_para()
    return blocks
