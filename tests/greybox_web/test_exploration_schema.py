"""Unit tests for the exploration reply contract (schema.py)."""
from __future__ import annotations

import json

import pytest

from src.greybox_web.exploration.schema import (
    ProposalError,
    extract_json,
    parse_reply,
    parse_structured,
    repair_message,
    PROPOSAL_SCHEMA,
)

VALID = {
    "reasoning": "The app has a login form and an API surface; both need targeted work.",
    "assessment": "incomplete",
    "todolist": [{"step": "Examine session cookies", "status": "in_progress"}],
    "hypotheses": [
        {"id": "h1", "label": "Broken API authorization",
         "hypothesis": "Object-level authorization between roles is missing.",
         "signals": {"surface": "api"}}],
    "actions": [
        {"tool": "cookies.flags", "params": {"url": "http://t/login"},
         "reason": "the login flow issues session cookies", "priority": 30,
         "variant": "Login Session", "hypothesis": "h1"}],
}


def test_parse_valid_reply():
    p = parse_reply(json.dumps(VALID))
    assert p.assessment == "incomplete"
    assert p.hypotheses[0].id == "h1"
    assert p.actions[0].variant == "login-session"          # normalized slug
    assert p.todolist[0].status == "in_progress"


def test_parse_inside_fenced_block_with_prose():
    text = "Here is my analysis:\n```json\n" + json.dumps(VALID) + "\n```\nDone."
    assert parse_reply(text).reasoning.startswith("The app")


def test_extract_json_balanced_nested():
    assert extract_json('prefix {"a": {"b": "}{"}} suffix') == '{"a": {"b": "}{"}}'


def test_unknown_fields_are_ignored_not_rejected():
    p = parse_reply(json.dumps({**VALID, "surprise": 1}))
    assert p.actions[0].tool == "cookies.flags"
    bad = json.loads(json.dumps(VALID))
    bad["actions"][0]["bonus"] = {"x": 1}
    bad["hypotheses"][0]["extra"] = True
    assert len(parse_reply(json.dumps(bad)).actions) == 1


def test_bad_hypothesis_id_is_coerced():
    bad = json.loads(json.dumps(VALID))
    bad["hypotheses"][0]["id"] = "Evil Id!!"
    bad["actions"][0]["hypothesis"] = "Evil Id!!"
    p = parse_reply(json.dumps(bad))
    assert p.hypotheses[0].id == "evil-id"
    assert p.actions[0].hypothesis == "evil-id"          # the reference still matches


def test_missing_hypothesis_id_is_generated_and_ids_stay_distinct():
    bad = json.loads(json.dumps(VALID))
    bad["hypotheses"] = [{"label": "First direction", "hypothesis": "a b c d e f g"},
                         {"id": "h1", "label": "Second", "hypothesis": "x y z w v u"},
                         {"id": "h1", "label": "Third", "hypothesis": "q r s t u v w"}]
    ids = [h.id for h in parse_reply(json.dumps(bad)).hypotheses]
    assert len(ids) == 3 and len(set(ids)) == 3


def test_unknown_assessment_defaults_to_incomplete():
    bad = json.loads(json.dumps(VALID))
    bad["assessment"] = "perfect"
    assert parse_reply(json.dumps(bad)).assessment == "incomplete"


def test_no_json_and_empty_object_are_failures():
    with pytest.raises(ProposalError, match="no JSON object"):
        parse_reply("no object here")
    with pytest.raises(ProposalError, match="no usable content"):
        parse_reply("{}")
    with pytest.raises(ProposalError):
        parse_reply('{"reasoning": 3, "actions": [], "unrelated": 1}'
                    .replace("3", "null"))


def test_truncated_json_keeps_the_complete_items():
    full = json.dumps(VALID)
    second = {"tool": "headers.security", "params": {"url": "http://t/"},
              "reason": "the root page needs a header review", "priority": 20}
    text = full[:-2] + ", " + json.dumps(second)[:-30]      # cut inside the 2nd action
    p = parse_reply(text)
    assert [a.tool for a in p.actions] == ["cookies.flags"]  # the cut action dropped
    assert p.repaired and p.assessment == "incomplete"
    assert p.hypotheses[0].id == "h1" and p.todolist


def test_truncated_inside_reasoning_keeps_what_was_said():
    p = parse_reply('{"reasoning": "The site is a Next.js app with many chunks and ')
    assert p.reasoning.startswith("The site is a Next.js app") and p.repaired


def test_truncated_reply_never_ends_the_assessment():
    p = parse_reply(json.dumps({**VALID, "assessment": "adequate", "actions": []})[:-1])
    assert p.assessment == "incomplete"
    p2 = parse_reply(json.dumps({**VALID, "assessment": "adequate", "actions": []}),
                     truncated=True)
    assert p2.assessment == "incomplete"


def test_prose_wrapped_and_unterminated_fence():
    text = "Thinking out loud first.\n```json\n" + json.dumps(VALID)
    assert parse_reply(text).reasoning.startswith("The app")
    text = "Result: " + json.dumps(VALID) + "\nHope this helps {not json}."
    assert parse_reply(text).hypotheses[0].id == "h1"


def test_trailing_commas_are_repaired():
    text = ('{"reasoning": "some honest analysis here", "todolist": [{"step": "a",},],'
            ' "actions": [],}')
    p = parse_reply(text)
    assert p.todolist[0].step == "a"


def test_one_bad_action_does_not_sink_the_rest():
    bad = json.loads(json.dumps(VALID))
    good = bad["actions"][0]
    bad["actions"] = [{"tool": "x"}, "not an object", {"params": {}},
                      dict(good, tool="has space inside"), good,
                      dict(good, tool="headers.security", priority="high")]
    p = parse_reply(json.dumps(bad))
    assert [a.tool for a in p.actions] == ["cookies.flags", "headers.security"]
    assert p.actions[1].priority == 15 and len(p.notes) == 4


def test_types_are_coerced_and_lengths_clamped():
    bad = json.loads(json.dumps(VALID))
    bad["actions"][0].update(priority="42", reason="r" * 900, title="t" * 500,
                             params='{"url": "http://t/x"}')
    bad["reasoning"] = "word " * 1000
    bad["todolist"] = ["a plain string step", {"step": "s" * 400, "status": "Done"}]
    p = parse_reply(json.dumps(bad))
    a = p.actions[0]
    assert a.priority == 42 and len(a.reason) == 400 and len(a.title) == 120
    assert a.params == {"url": "http://t/x"}
    assert len(p.reasoning) <= 2000
    assert p.todolist[0].step == "a plain string step"
    assert len(p.todolist[1].step) == 200 and p.todolist[1].status == "done"


def test_priority_is_clamped_and_item_counts_are_capped():
    bad = json.loads(json.dumps(VALID))
    bad["actions"] = [dict(VALID["actions"][0], priority=999, variant=f"v{i}")
                      for i in range(12)]
    p = parse_reply(json.dumps(bad))
    assert len(p.actions) == 8 and p.actions[0].priority == 90
    assert any("beyond 8" in n for n in p.notes)


def test_wrapped_payload_is_unwrapped():
    p = parse_reply(json.dumps({"propose": VALID}))
    assert p.actions[0].tool == "cookies.flags"


def test_parse_structured_accepts_a_tool_input():
    p = parse_structured(VALID)
    assert p.assessment == "incomplete" and not p.repaired
    assert parse_structured(VALID, truncated=True).repaired


def test_proposal_schema_is_a_json_schema_for_the_contract():
    props = PROPOSAL_SCHEMA["properties"]
    assert set(props) >= {"reasoning", "assessment", "todolist", "hypotheses",
                          "actions"}
    json.dumps(PROPOSAL_SCHEMA)


def test_repair_message_is_model_facing():
    m = repair_message(ProposalError("the reply is not valid JSON (boom)"))
    assert "NOT applied" in m and "JSON object only" in m and "concise" in m


def test_extract_json_strips_code_fence_only_first_block():
    text = "```json\n{}\n```\n```json\n{}\n```"
    assert extract_json(text) == "{}"


# ------------------------------------------------- replies to operator messages


def test_replies_are_parsed_normalised_and_clamped():
    p = parse_reply(json.dumps({**VALID, "replies": [
        {"id": "M1", "reply": "I will look at /admin next."},
        {"id": "m1", "reply": "a second reply to the same id is ignored"},
        {"id": "m2", "reply": "x" * 1000},
        {"id": "m3"},                                   # no text: dropped
        "not an object"]}))
    assert [r.id for r in p.replies] == ["m1", "m2"]
    assert p.replies[0].reply == "I will look at /admin next."
    assert len(p.replies[1].reply) == 300
    assert any("reply #4" in n for n in p.notes) and any("reply #5" in n for n in p.notes)


def test_replies_as_a_mapping_and_replies_only_reply_is_usable():
    p = parse_structured({"replies": {"m1": "Noted, focusing on the API."}})
    assert [(r.id, r.reply) for r in p.replies] == [("m1", "Noted, focusing on the API.")]
    assert parse_reply(json.dumps(VALID)).replies == []       # optional


def test_schema_advertises_replies():
    rep = PROPOSAL_SCHEMA["properties"]["replies"]
    assert rep["items"]["required"] == ["id", "reply"]
    assert rep["items"]["properties"]["reply"]["maxLength"] == 300
    assert "replies" not in PROPOSAL_SCHEMA["required"]
