"""authz.exposure — multi-step verification of a cross-interface access boundary.

Pure decision table, then live runs: a real boundary crossing on Harbor Docs
(activity feed vs project API), and the ordinary explanations that must NOT be
findings (an authorised member; the clean intranet's intended staff directory).
"""
from __future__ import annotations

import pytest

from src.greybox_web.tools import auth
from src.greybox_web.tools import xref
from src.greybox_web.tools.xref import Step, decide
from tests.greybox_web.fixtures import fjord_intranet, harbor_docs
from tests.greybox_web.test_auth_login import ctx_for


def S(status, contains=None, ident="v", url="http://t.test/interface"):
    return Step("s", url, ident, status=status, contains=contains)


@pytest.mark.parametrize("view,anon,control,owner,canon,want", [
    (S(200, False), None, S(403), None, None, xref.NOT_PRESENT),
    (S(403, True), None, S(403), None, None, xref.NOT_PRESENT),
    (S(200, True), S(200, True), S(404), None, S(200), xref.PUBLIC),
    (S(200, True), None, S(200), None, None, xref.AUTHORISED),
    (S(200, True), None, S(403), None, None, xref.UNKNOWN),
    (S(200, True), None, S(401), None, None, xref.UNKNOWN),
    (S(200, True), None, S(403), S(200, True), None, xref.CROSSED),
    (S(200, True), None, S(404), S(200, True), None, xref.CROSSED),
    (S(200, True), None, S(404), None, None, xref.UNKNOWN),        # exists? unknown
    (S(200, True), None, S(404), S(404), None, xref.UNKNOWN),
    (S(200, True), None, S(403), S(200, False), None, xref.UNKNOWN),  # not its data
    (S(200, True), None, S(502), None, None, xref.UNKNOWN),
])
def test_decision_table(view, anon, control, owner, canon, want):
    assert decide(view, anon, control, owner, canon)[0] == want


def test_anonymous_capability_link_is_authorised_not_cross_interface_exposure():
    share = S(200, True, "viewer", "http://t.test/share/abcdefghijk")
    anonymous = S(200, True, "anon", share.url)
    assert decide(share, anonymous, S(403), S(200, True), None)[0] == xref.AUTHORISED


def test_marker_matching_does_not_correlate_identifier_substrings():
    assert xref._marker_present('{"title":"Cobalt project"}', "Cobalt")
    assert not xref._marker_present('{"id":"doc-123"}', "doc-12")


@pytest.fixture(scope="module")
def harbor():
    server, url = harbor_docs.serve(0)
    yield url
    server.should_exit = True


@pytest.fixture(scope="module")
def fjord():
    server, url = fjord_intranet.serve(0)
    yield url
    server.should_exit = True


async def _login(mk, url, path, *labels):
    for label in labels:
        res = await auth.login(mk({"url": url + path, "account": label,
                                   "user_field": "username"}))
        assert res.counts.get("established") == 1, res.summary


async def test_feed_describes_a_project_its_api_refuses(harbor):
    async with ctx_for(harbor, "harbor_docs") as (mk, client, rec):
        await _login(mk, harbor, "login", "dave", "finn")
        params = {"url": harbor + "api/teams/meridian/activity", "viewer": "dave",
                  "marker": "Cobalt — layoffs scenario Q3",
                  "control_url": harbor + "api/projects/cobalt", "owner": "finn"}
        ctx = mk(params)
        ctx.http = client.bind("authz.exposure")
        res = await xref.exposure(ctx)
        facts = res.observations[0].facts
        # the marker is a document title: the project interface served to its
        # owner does not contain it, so the boundary is not established this way
        assert facts["decision"] in (xref.UNKNOWN, xref.CROSSED)
        params["marker"] = "Cobalt"
        res = await xref.exposure(_with(ctx, params))
        f = res.observations[0].facts
        assert f["decision"] == xref.CROSSED, f
        assert len(res.findings) == 1
        finding = res.findings[0]
        assert finding.finding_class == "vulnerability" and finding.identity == "dave"
        assert finding.asset_url == params["control_url"]
        assert "Expected boundary" in finding.description
        assert len([e for e in finding.evidence if e.exchange_id]) >= 3
        # the steps really ran as the stated identities
        assert {r.identity for r in rec.rows[-5:]} >= {"dave", "finn", "anon"}
        # independent re-check reaches the same decision
        v = await xref.verify(_with(ctx, finding.verify))
        assert v.confirmed, v.note


def _with(ctx, params):
    ctx.params = dict(params)
    return ctx


async def test_an_authorised_member_is_not_a_finding(harbor):
    async with ctx_for(harbor, "harbor_docs") as (mk, client, _):
        await _login(mk, harbor, "login", "dave")
        ctx = mk({"url": harbor + "api/teams/meridian/activity", "viewer": "dave",
                  "marker": "Beacon", "control_url": harbor + "api/projects/beacon"})
        ctx.http = client.bind("authz.exposure")
        res = await xref.exposure(ctx)
        assert res.observations[0].facts["decision"] == xref.AUTHORISED
        assert res.findings == []


async def test_intended_directory_data_is_not_a_boundary_crossing(fjord):
    """The staff directory shows colleagues' work e-mail on purpose; jonas's
    payslip is refused to sofia. A person's e-mail is not that payslip's data:
    the owner binding keeps this from becoming a finding."""
    async with ctx_for(fjord, "fjord_intranet") as (mk, client, _):
        await _login(mk, fjord, "login", "sofia", "jonas")
        ctx = mk({"url": fjord + "api/directory?per_page=50", "viewer": "sofia",
                  "marker": "jonas",
                  "control_url": fjord + "api/payslips/1a4d7f0c-3e6b-4d9a-a2c5-"
                                         "8e1b4f7a0d44",
                  "owner": "jonas"})
        ctx.http = client.bind("authz.exposure")
        res = await xref.exposure(ctx)
        assert res.findings == [], res.observations[0].facts


async def test_claims_are_validated(harbor):
    async with ctx_for(harbor, "harbor_docs") as (mk, client, _):
        bad = [{"url": harbor + "api/projects/cobalt", "viewer": "dave",
                "marker": "cobalt", "control_url": harbor + "api/projects/x"},  # echo
               {"url": harbor + "a", "viewer": "dave", "marker": "ab",
                "control_url": harbor + "b"},                                   # short
               {"url": harbor + "a", "viewer": "nobody", "marker": "abcd",
                "control_url": harbor + "b"}]                                   # unknown
        for p in bad:
            ctx = mk(p)
            ctx.http = client.bind("authz.exposure")
            with pytest.raises(ValueError):
                await xref.exposure(ctx)
