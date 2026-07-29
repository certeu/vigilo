import pytest
from src.greybox.discovery.shape_inference import infer_shape


@pytest.mark.parametrize("name,sample,openapi_type,expected", [
    ("user_id", "42", None, "numeric_id"),
    ("id", "550e8400-e29b-41d4-a716-446655440000", None, "uuid"),
    ("email", "a@b.com", None, "email"),
    ("callback_url", "https://example.com/cb", None, "url"),
    ("enabled", "true", "boolean", "boolean"),
    ("status", "active", None, "free_text"),
    ("payload", '{"k":1}', None, "json"),
    ("category", "red", None, "free_text"),
    ("filter_type", None, "string", "free_text"),
])
def test_infer_shape(name, sample, openapi_type, expected):
    assert infer_shape(name, sample, openapi_type) == expected


def test_shape_respects_openapi_over_name():
    # An OpenAPI spec is authoritative when present
    assert infer_shape("count", "not-a-number", openapi_type="integer") == "numeric_id"
