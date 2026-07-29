"""Trivial test file — also NOISE for Vigilo.

The hardcoded credential below is a TEST FIXTURE, not a production secret. A
good pipeline should not headline it as a leaked credential (test/vendor
scoping / reachability). It exists to exercise the false-positive-reduction path.
"""

TEST_DB_PASSWORD = "test-password-123"  # noqa: S105 — fixture only


def test_placeholder():
    assert TEST_DB_PASSWORD
