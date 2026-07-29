from src.greybox.graph.schema import ParameterNode


def test_parameter_accepts_shape_numeric_id():
    p = ParameterNode(
        name="user_id",
        location="path",
        data_type="string",
        discovered_by="discovery",
        shape="numeric_id",
    )
    assert p.shape == "numeric_id"


def test_parameter_default_shape_is_free_text():
    p = ParameterNode(
        name="bio",
        location="body",
        data_type="string",
        discovered_by="discovery",
    )
    assert p.shape == "free_text"


def test_parameter_rejects_invalid_shape():
    import pytest
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        ParameterNode(
            name="x", location="query", data_type="string",
            discovered_by="discovery", shape="not_a_shape",
        )


from src.greybox.graph.schema import EDGE_TYPES


def test_reflects_in_edge_registered():
    assert "reflects_in" in EDGE_TYPES
    assert EDGE_TYPES["reflects_in"] == {"from": "parameter", "to": "endpoint"}


def test_produced_from_edge_registered():
    assert "produced_from" in EDGE_TYPES
    assert EDGE_TYPES["produced_from"] == {
        "from": "lead", "to": "test_attempt",
    }


def test_data_flows_to_edge_registered():
    assert "data_flows_to" in EDGE_TYPES
    assert EDGE_TYPES["data_flows_to"] == {
        "from": "parameter", "to": "technology",
    }


def test_derived_from_edge_registered():
    assert "derived_from" in EDGE_TYPES
    assert EDGE_TYPES["derived_from"] == {
        "from": "finding", "to": "test_attempt",
    }
