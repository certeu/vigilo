"""Diagram 1: the two ways to run Vigilo (docs/images/modes-overview.png)."""
from manim import Scene, VGroup, DOWN, UP, LEFT, RIGHT
from style import *

setup(20, 11)

PANEL_W, PANEL_H, PANEL_Y = 9.0, 4.4, 0.7
OUT_Y = -3.4


def mode_panel(x, name, tagline, inputs, outputs):
    box = panel(PANEL_W, PANEL_H, name, tagline, title_size=40)
    box.move_to([x, PANEL_Y, 0])
    chips = VGroup(*[node(t, s, w=3.6, h=1.5, title_size=30, sub_size=22) for t, s in inputs])
    chips.arrange(RIGHT, buff=0.8).move_to([x, PANEL_Y - 0.8, 0])
    plus = text("+", 44, MUTED, bold=True).move_to(chips.get_center())
    out = node(outputs[0], outputs[1], w=PANEL_W - 1.0, h=1.6, fill=GREEN, edge=GREEN_EDGE,
               title_size=32, sub_size=23).move_to([x, OUT_Y, 0])
    down = arrow(box.box.get_bottom(), out.get_top(), width=6, tip=0.3, buff=0.06)
    return VGroup(box, chips, plus, out, down), box


class ModesOverview(Scene):
    def construct(self):
        top = node("VIGILO", None, w=4.2, h=1.1, fill=ACCENT, edge=ACCENT,
                   title_size=44, title_color=BG).move_to([0, 4.55, 0])
        wb, wbox = mode_panel(-5.2, "White-box", "Source code review",
            [("Source code", "static analysis"), ("Running app", "dynamic proof")],
            ("Report + patches", "evidence, fix branch per confirmed finding"))
        gb, gbox = mode_panel(5.2, "Grey-box", "Running-app assessment",
            [("Running app", "no source code"), ("Credentials", "one or more identities")],
            ("Report + detection hints", "WAF rules, log signatures, SIEM queries"))
        yb = 3.75
        bus = [line(top.get_bottom(), [0, yb, 0]), line([-5.2, yb, 0], [5.2, yb, 0]),
               arrow([-5.2, yb, 0], wbox.box.get_top(), width=5, buff=0.0),
               arrow([5.2, yb, 0], gbox.box.get_top(), width=5, buff=0.0)]
        self.add(top, wb, gb, *bus)
