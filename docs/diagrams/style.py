"""Shared look for the Vigilo README diagrams: palette, fonts and drawing helpers.

Every scene calls ``setup(width, height)`` at import time so the still comes out
at ~2400 px wide with a solid background (readable in GitHub light and dark).
"""
from __future__ import annotations

import os

from manim import (
    DOWN, LEFT, RIGHT, UP, Arrow, DashedVMobject, Line, MarkupText,
    RoundedRectangle, VGroup, config,
)

# --- palette (solid navy background; same family as the screenshots) --------
BG = "#171E3A"
PANEL = "#222B52"        # grouping panels
PANEL_EDGE = "#3A4778"
NODE = "#2C3B7A"         # ordinary node
NODE_EDGE = "#5B8DEF"
ACCENT = "#F2A65A"       # orange: titles, the Vigilo brand colour
LEDGER = "#0F6E6A"       # teal: the findings ledger and its records
LEDGER_EDGE = "#3FD0C4"
GREEN = "#2F7D55"        # outputs / deliverables
GREEN_EDGE = "#5FD39A"
PURPLE = "#5B3F9B"       # optional / preset-dependent stages
PURPLE_EDGE = "#B39DF5"
RED = "#8F3A4A"          # halt conditions
RED_EDGE = "#F08A9B"
TEXT = "#F5F7FC"
MUTED = "#B4BEDD"
ARROW = "#8FB4FF"

FONT = os.environ.get("VIGILO_DIAGRAM_FONT", "Helvetica")


def setup(width: float, height: float, pixel_width: int = 3600) -> None:
    """Frame size in scene units; render size follows at ``pixel_width``."""
    config.frame_width = width
    config.frame_height = height
    config.pixel_width = pixel_width
    config.pixel_height = round(pixel_width * height / width)
    config.background_color = BG


def text(s: str, size: float = 26, color: str = TEXT, bold: bool = False,
         max_width: float | None = None) -> MarkupText:
    t = MarkupText(s, font=FONT, font_size=size, color=color,
                   weight="BOLD" if bold else "NORMAL")
    if max_width is not None and t.width > max_width:
        t.scale_to_fit_width(max_width)
    return t


def node(title: str, sub: str | None = None, w: float = 3.0, h: float = 1.2,
         fill: str = NODE, edge: str = NODE_EDGE, title_size: float = 28,
         sub_size: float = 21, title_color: str = TEXT, dashed: bool = False) -> VGroup:
    """Rounded box with a bold title and an optional muted second line."""
    box = RoundedRectangle(corner_radius=0.16, width=w, height=h, fill_color=fill,
                           fill_opacity=1, stroke_color=edge, stroke_width=3)
    parts = [text(title, title_size, title_color, bold=True, max_width=w - 0.4)]
    for sub_line in (sub.split("\n") if sub else []):
        parts.append(text(sub_line, sub_size, MUTED, max_width=w - 0.4))
    labels = VGroup(*parts).arrange(DOWN, buff=0.1)
    if labels.height > h - 0.2:
        labels.scale_to_fit_height(h - 0.2)
    labels.move_to(box)
    group = VGroup(box, labels)
    if dashed:
        dashed_box = DashedVMobject(box.copy().set_fill(opacity=0), num_dashes=40)
        box.set_stroke(width=0)
        group.add(dashed_box)
    group.box = box  # type: ignore[attr-defined]
    return group


def panel(w: float, h: float, title: str | None = None, sub: str | None = None,
          fill: str = PANEL, edge: str = PANEL_EDGE, title_color: str = ACCENT,
          title_size: float = 32) -> VGroup:
    """Large grouping container; the heading sits inside the top edge."""
    box = RoundedRectangle(corner_radius=0.25, width=w, height=h, fill_color=fill,
                           fill_opacity=1, stroke_color=edge, stroke_width=3)
    group = VGroup(box)
    if title:
        head = text(title, title_size, title_color, bold=True, max_width=w - 0.6)
        head.move_to(box.get_top() + DOWN * 0.45)
        group.add(head)
        if sub:
            s = text(sub, 22, MUTED, max_width=w - 0.6)
            s.next_to(head, DOWN, buff=0.1)
            group.add(s)
    group.box = box  # type: ignore[attr-defined]
    return group


def arrow(start, end, color: str = ARROW, width: float = 4, dashed: bool = False,
          both: bool = False, buff: float = 0.08, tip: float = 0.22) -> Arrow | VGroup:
    a = Arrow(start, end, buff=buff, color=color, stroke_width=width,
              max_tip_length_to_length_ratio=0.35, tip_length=tip,
              max_stroke_width_to_length_ratio=100)
    if both:
        a.add_tip(at_start=True)
    return a


def line(start, end, color: str = ARROW, width: float = 4) -> Line:
    return Line(start, end, color=color, stroke_width=width)


def caption(s: str, size: float = 22, color: str = MUTED, max_width: float | None = None):
    return text(s, size, color, max_width=max_width)


__all__ = [n for n in dir() if not n.startswith("_")] + ["LEFT", "RIGHT", "UP", "DOWN"]
