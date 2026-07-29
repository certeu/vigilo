"""Lead investigator context builder.

Builds context for the investigator agent to explore a lead signal,
including hypothesis, hints, and remaining investigation budget.
"""
from __future__ import annotations


def build_investigator_context(lead: dict, max_attempts: int = 3) -> str:
    """Build context for investigating a lead signal.

    Includes: lead ID, signal type, strength, target, hypothesis, hints,
    and remaining budget (max_attempts - attempt_count).
    """
    lead_id = lead.get("id", "unknown")
    signal_type = lead.get("signal_type", "unknown")
    strength = lead.get("strength", lead.get("confidence", "medium"))
    target = lead.get("url", lead.get("target", "unknown"))
    hypothesis = lead.get("hypothesis", "")
    hints = lead.get("hints", [])
    attempt_count = lead.get("attempt_count", 0)
    remaining_budget = max_attempts - attempt_count

    lines = [
        "## Lead to Investigate",
        "",
        f"- **Lead ID**: {lead_id}",
        f"- **Signal Type**: {signal_type}",
        f"- **Strength**: {strength}",
        f"- **Target**: {target}",
        f"- **Hypothesis**: {hypothesis}" if hypothesis else None,
        "",
    ]

    if hints:
        lines.append("### Hints")
        for hint in hints:
            lines.append(f"- {hint}")
        lines.append("")

    lines.extend([
        "### Budget",
        f"- **Remaining attempts**: {remaining_budget} of {max_attempts}",
        "",
        "Investigate this lead and determine if it represents a real vulnerability. "
        "Be efficient with your remaining budget.",
    ])

    return "\n".join(line for line in lines if line is not None)
