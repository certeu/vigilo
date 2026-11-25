from src.greybox_web.exploration.schema import parse_structured
from src.greybox_web.investigation import (
    discover_operations,
    investigation_from_lead,
    investigations_from_operations,
    priority_for_investigation,
    stable_operation_id,
)
from src.greybox_web.planning import LeadSpec, WorkOrderSpec


def _declaration(*, satisfied=True, steps=1):
    return {
        "operation": {"id": "op-change", "protocol": "graphql",
                      "identity": "mutation changeOwner"},
        "expected_property": "only privileged roles may transfer ownership",
        "prerequisites": [{"name": "two identities", "required": True,
                           "status": "satisfied" if satisfied else "missing"}],
        "required_observations": ["owner before", "owner after"],
        "planned_verification": {"steps": [str(index) for index in range(steps)]},
        "progress": {"completed_steps": []},
    }


def test_operation_identity_is_protocol_aware_and_stable():
    assert stable_operation_id("graphql", "query asset") == stable_operation_id(
        "graphql", "query asset")
    assert stable_operation_id("graphql", "query asset") != stable_operation_id(
        "jsonrpc", "query asset")


def test_operation_discovery_preserves_declared_permissions_and_unknowns():
    operations = discover_operations([
        {"url": "/api/items", "methods": ["GET", "POST"],
         "security": [{"role": "operator", "basis": "documented"}],
         "source": ["openapi"]},
    ])
    assert [operation.identity for operation in operations] == [
        "GET /api/items", "POST /api/items"]
    assert operations[0].permissions == ({"role": "operator", "basis": "documented"},)
    assert operations[0].state_effects == ()


def test_operation_discovery_merges_richer_observation_without_mistaking_name_for_identity():
    operations = discover_operations([
        {"operations": [{"id": "op-approve", "protocol": "graphql",
                         "identity": "mutation approveChange"}]},
        {"operations": [{"id": "op-approve", "protocol": "graphql",
                         "identity": "mutation approveChange", "input_fields": ["id", "note"],
                         "resources": ["change-17"], "identities": ["member"],
                         "state_effects": ["approval state changes"]}]},
    ])
    assert len(operations) == 1
    assert operations[0].input_structure == {"fields": ["id", "note"]}
    assert operations[0].resources == ("change-17",)
    assert operations[0].identities == ("member",)


def test_actionable_context_contains_capabilities_resource_and_verification_candidates():
    operation = discover_operations([{"operations": [{
        "id": "op-approve", "protocol": "graphql", "identity": "mutation approveChange",
        "parameters": {"id": "ID!", "note": "String"}, "resources": ["change-17"],
        "documented_roles": ["approver"], "state_effects": ["approval state changes"],
    }]}])[0]
    view = investigations_from_operations(
        [operation], available_identities=["member", "approver"],
        execution_capabilities=["api.operation.invoke", "tool.create"])[0].as_dict()
    assert view["progress_state"] == "ready"
    assert view["configured_identities"] == ["member", "approver"]
    assert view["relevant_resources"] == ["change-17"]
    assert view["missing_prerequisites"] == []
    assert view["possible_next_actions"][0]["operation_ref"] == "op-approve"
    assert view["possible_next_actions"][0]["tool"] == "api.operation.invoke"


def test_sparse_persistent_lead_is_enriched_from_operation_record():
    operation = discover_operations([{"operations": [{
        "id": "op-approve", "protocol": "graphql", "identity": "mutation approveChange",
        "input_fields": ["id"], "resources": ["change-17"],
    }]}])[0]
    data = {"hypothesis": "member can approve", "signals": {"investigation": {
        "operation_id": "op-approve", "expected_property": "approver required",
        "prerequisites": [{"name": "identity contexts", "status": "satisfied"}],
        "planned_verification": {"steps": ["act", "verify"]},
    }}}
    view = investigation_from_lead(
        "lead:x", "open", None, data, operation_record=operation,
        configured_identities=["member", "approver"],
        execution_capabilities=["api.operation.invoke"]).as_dict()
    assert view["operation"]["identity"] == "mutation approveChange"
    assert view["known_parameters"]["input"] == {"fields": ["id"]}
    assert view["possible_next_actions"][0]["resource_options"] == ["change-17"]


def test_schema_preserves_operation_aware_investigation_declaration():
    proposal = parse_structured({
        "reasoning": "A decisive verification is ready.",
        "assessment": "incomplete",
        "hypotheses": [{"id": "transfer", "label": "Transfer boundary",
                        "hypothesis": "A member may transfer ownership",
                        **_declaration()}],
        "actions": [{"tool": "dyn.transfer", "params": {}, "reason": "verify",
                     "priority": 50, "hypothesis": "transfer"}],
    })
    declaration = proposal.hypotheses[0].signals["investigation"]
    assert declaration["operation"]["id"] == "op-change"
    assert proposal.hypotheses[0].expected_property.startswith("only privileged")


def test_ready_one_step_verification_is_promoted():
    lead = LeadSpec("explorer", "lead:x", "x", "test x",
                    signals={"investigation": _declaration()})
    work = WorkOrderSpec("dyn.transfer", {}, "verify", priority=50, lead=lead)
    assert work.priority == 7
    assert priority_for_investigation(50, _declaration(satisfied=False)) == 50


def test_persistent_lead_projects_resume_and_budget_outcomes():
    data = {"hypothesis": "state transition crosses a role boundary",
            "signals": {"investigation": _declaration(steps=3)}}
    resumed = investigation_from_lead("lead:x", "investigating", None, data,
                                      available_tools=["dyn.transfer"])
    exhausted = investigation_from_lead("lead:y", "open", None, data,
                                        budget_exhausted=True)
    assert resumed.status == "in_progress"
    assert resumed.available_tools == ("dyn.transfer",)
    assert exhausted.as_dict()["status"] == "budget_exhausted"


def test_lead_outcomes_distinguish_verified_rejected_and_inconclusive():
    data = {"hypothesis": "boundary", "signals": {"investigation": _declaration()}}
    assert investigation_from_lead("a", "confirmed", "reported",
                                   {**data, "basis": "verified_finding"}).status == "verified"
    assert investigation_from_lead("b", "refuted", "ruled_out", data).status == "rejected"
    assert investigation_from_lead("c", "inconclusive", "needs_follow_up", data).status == "inconclusive"


def test_investigation_context_uses_active_snapshot_and_clean_check_stays_open():
    from src.greybox_web.exploration.explorer import Explorer
    from src.greybox_web.exploration.proposer import LlmProposer
    assert "FOLLOW-THROUGH" in Explorer._investigation_section(
        {"investigations": {"active": [{"status": "ready"}]}})
    proposal = parse_structured({"hypotheses": [{"id": "h", "label": "boundary",
        "hypothesis": "expected denial", "investigation": {**_declaration(), "id": "durable",
        "next_action": {"tool": "api.compare_access", "required_observation": "matrix"}}}],
        "actions": [{"tool": "api.compare_access", "params": {}, "reason": "observe", "hypothesis": "h"}]})
    proposer = LlmProposer(); proposer.store(proposal, model="test", tokens=1)
    assert proposer.stored.groups[0].specs[0].lead is not None
    assert proposer.stored.groups[0].specs[0].lead.investigation["id"] == "durable"
    assert proposer.stored.leads[0].investigation["id"] == "durable"
