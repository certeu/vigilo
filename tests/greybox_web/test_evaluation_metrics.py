from scripts.greybox_eval import investigation_metrics


def _investigation(identifier, status, *, ready_at=None):
    return {
        "id": identifier,
        "kind": "lead",
        "data": {
            "signals": {
                "investigation": {
                    "id": identifier,
                    "status": status,
                    "ready_at": ready_at,
                }
            }
        },
    }


def _work(identifier, tool, *, created_at=None):
    return {
        "id": f"work-{identifier}-{tool}",
        "kind": "work_order",
        "created_at": created_at,
        "data": {"tool": tool, "investigation_ref": identifier},
    }


def test_investigation_metrics_measure_follow_through_without_counting_discovery():
    graph = {
        "nodes": [
            _investigation("ready", "ready", ready_at="2026-11-24T10:00:00Z"),
            _investigation("done", "confirmed", ready_at="2026-11-24T10:00:00Z"),
            _investigation("new", "discovered"),
            _work("ready", "discovery.crawl", created_at="2026-11-24T10:00:05Z"),
            _work("done", "api.operation.invoke", created_at="2026-11-24T10:00:07Z"),
        ]
    }
    assert investigation_metrics(graph, []) == {
        "persisted": 3,
        "ready": 2,
        "attempted": 1,
        "completed": 1,
        "initiation_rate": 0.5,
        "completion_rate": 1.0,
        "time_to_first_meaningful_test_s": 7.0,
        "repeated_discovery_without_progress": 1,
        "unattempted_ready": ["ready"],
    }


def test_investigation_metrics_reports_old_run_latency_as_unknown():
    result = investigation_metrics(
        {"nodes": [_investigation("legacy", "ready"), _work("legacy", "authz.object")]},
        [{"kind": "planner.decision", "data": {"reason": "no_new_information"}}],
    )
    assert result["attempted"] == 1
    assert result["time_to_first_meaningful_test_s"] is None
    assert result["repeated_discovery_without_progress"] == 1
