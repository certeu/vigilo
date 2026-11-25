from src.greybox_web.secmodel import observe


def test_graphql_and_rpc_operations_are_distinct_interfaces():
    rows = [
        {"id": 1, "url": "http://api.test/graphql", "method": "POST", "status_code": 200, "identity": "member", "tool": "tool.gql", "blocked": False, "content_type": "application/json", "request_body": '{"query":"mutation Approve($id: ID!){ approveChange(id:$id){ id } }"}'},
        {"id": 2, "url": "http://api.test/rpc", "method": "POST", "status_code": 403, "identity": "member", "tool": "tool.rpc", "blocked": False, "content_type": "application/json", "request_body": '{"jsonrpc":"2.0","method":"admin.update"}'},
    ]
    got = observe(rows, {"member"})
    assert got[0].interface.endswith("#Approve") and got[0].operation == "act"
    assert got[1].interface.endswith("#admin.update") and got[1].operation == "act"
