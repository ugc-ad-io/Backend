"""Senior-tester additions to tests/test_deal_scenarios.py.

Same approach as the junior file (real FastAPI routes, mongomock-motor, no network), reusing its
World/scenario helpers. What is new here:

  * requests are made EXACTLY like the shipped clients make them (no deliverable_index; website
    approve endpoint), where the junior's helpers always send the index,
  * a "yielding" database proxy + httpx AsyncClient, so two requests really interleave at every
    database call (double click on hire / approve / finish-hiring / submit / reject),
  * lifecycle gaps (decline then resubmit, revoke, expiry, banned brief hire, refund of the fee),
  * revision loop money, odd budgets with TDS switched on.

Tests that demonstrate a production bug are xfail(strict=False, reason="BUG: ...").
Run with --runxfail to see them fail. Nothing here touches a real database.
"""
import asyncio
import inspect

import httpx
import pytest

pytest.importorskip("mongomock_motor")

import server  # noqa: E402
from tests import test_deal_scenarios as ds  # noqa: E402  (module import: nothing of it is re-collected)


@pytest.fixture
def w(monkeypatch):
    world = ds.World(monkeypatch)
    yield world
    world.close()


# ---------------------------------------------------------------------------------------------
# Yielding database: every collection call gives the other request a turn first.
# ---------------------------------------------------------------------------------------------
class _YCursor:
    def __init__(self, cur):
        self._c = cur

    def __getattr__(self, name):
        attr = getattr(self._c, name)
        if name == "to_list":
            async def to_list(*a, **k):
                await asyncio.sleep(0)
                return await attr(*a, **k)
            return to_list
        if callable(attr):
            def chained(*a, **k):
                r = attr(*a, **k)
                return _YCursor(r) if hasattr(r, "to_list") else r
            return chained
        return attr

    def __aiter__(self):
        async def gen():
            async for d in self._c:
                await asyncio.sleep(0)
                yield d
        return gen()


class _YColl:
    def __init__(self, coll):
        self._c = coll

    def __getattr__(self, name):
        attr = getattr(self._c, name)
        if not callable(attr):
            return attr

        def call(*a, **k):
            r = attr(*a, **k)
            if inspect.isawaitable(r):
                async def co():
                    await asyncio.sleep(0)
                    return await r
                return co()
            return _YCursor(r) if hasattr(r, "to_list") else r
        return call


class _YDB:
    def __init__(self, db):
        self._db = db

    def __getattr__(self, name):
        return _YColl(getattr(self._db, name))

    def __getitem__(self, name):
        return _YColl(self._db[name])


def concurrently(w, monkeypatch, calls):
    """calls = [(method, path, token, json|None), ...] fired at the same time, interleaving at each db call."""
    monkeypatch.setattr(server, "db", _YDB(w.db))

    async def go():
        transport = httpx.ASGITransport(app=server.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as cl:
            return await asyncio.gather(*[
                cl.request(m, "/api" + p, headers={"Authorization": f"Bearer {t}"}, **({"json": j} if j is not None else {}))
                for m, p, t, j in calls])
    try:
        return w.run(go())
    finally:
        monkeypatch.setattr(server, "db", w.db)


def test_harness_really_interleaves(w, monkeypatch):
    """Control for the concurrency tests: with the proxy two read-then-write tasks alternate."""
    log = []
    ydb = _YDB(w.db)

    async def task(name):
        await ydb.probe.find_one({})
        log.append(name + "-read")
        await ydb.probe.insert_one({"n": name})
        log.append(name + "-write")

    async def go():
        await asyncio.gather(task("A"), task("B"))
    w.run(go())
    assert log == ["A-read", "B-read", "A-write", "B-write"], log


# ---------------------------------------------------------------------------------------------
# 1. Private brief: accept, work, approve, get paid (B1 re-derived with the website's own calls)
# ---------------------------------------------------------------------------------------------
class TestPrivateBriefPaysTheCreator:
    @pytest.mark.xfail(strict=False, reason=(
        "BUG (B1): plain accept of a private brief never turns the 'reserved' pool into a held escrow for the "
        "creator (activate_deal_from_card early return, server.py 8944-8951), so the website's approve "
        "(POST /deals/{id}/approve) answers 'Content approved.' and pays 0"))
    @pytest.mark.parametrize("n", [1, 2])
    def test_accept_submit_website_approve_pays_80_percent(self, w, n):
        ctx = w.start(n)
        ct, c = ctx.creators[0]
        assert w.submit(ctx.cid, ct, 0).status_code == 200
        r = w.call("POST", f"/deals/{ctx.cid}/approve", w.brand_t)        # WorkReview.js:519
        assert r.status_code == 200, r.text
        assert w.balance(c) == pytest.approx(800.0), r.json()

    @pytest.mark.xfail(strict=False, reason=(
        "BUG (B1): the wizard tells the brand 'hold 1000 + 20% fee 200 + listing 500 = 1700', but accepting a "
        "private brief never collects the 200 fee (same early return)"))
    def test_accept_collects_the_brand_fee_the_wizard_promised(self, w):
        ctx = w.start(1)
        assert ctx.initial - w.balance(w.brand) == pytest.approx(1700.0)

    def test_control_countered_private_brief_does_convert_the_pool(self, w):
        """Control: the counter path (covered by test_private_counter.py) is wired; the plain accept is not."""
        ctx = w.start(1)
        pool = [e for e in w.escrows(ctx.cid)]
        assert [(e["status"], e["creator_id"]) for e in pool] == [("reserved", None)]   # pins today's (wrong) state


# ---------------------------------------------------------------------------------------------
# 2. Multi-slot deals the way the real clients call them (B2 / B3 / B4)
# ---------------------------------------------------------------------------------------------
def website_submit(w, cid, token, n=0):
    """OrderRoom.js:189 / MyDealsPage.js:523 body: NO deliverable_index."""
    return w.call("POST", f"/deals/{cid}/content", token, json={
        "video_url": f"https://cdn.example.com/site-{n}.mp4", "creator_note": "Submitted from creator deal room"})


class TestMultiSlotWithShippedClients:
    def test_omitted_index_always_means_slot_zero_server_does_not_pick_the_next_free_slot(self, w):
        """Pins the server contract the report depends on (server.py 11613, 11653, 10665)."""
        ctx = w.start(9)
        ct, c = ctx.creators[0]
        assert website_submit(w, ctx.cid, ct, 0).json()["message"] == "Content submitted"
        again = website_submit(w, ctx.cid, ct, 1)
        assert again.status_code == 200 and again.json()["message"] == "Content already submitted"
        assert [x["deliverable_index"] for x in w.works(ctx.cid, c)] == [0]
        assert w.approve_pending(ctx, c)                                    # slot 0 approved
        third = website_submit(w, ctx.cid, ct, 2)
        assert third.status_code == 400 and "already approved" in third.text
        assert w.balance(c) == 0 and [e["status"] for e in w.escrows(ctx.cid)] == ["held"]

    @pytest.mark.xfail(strict=False, reason=(
        "BUG (B2/B4): a creator using the website deal room and a brand using the website Work Review can only ever "
        "deliver and approve slot 0, so a quantity>1 / multi-row deal is never paid (server.py 11613, 13015)"))
    @pytest.mark.parametrize("n", [7, 8, 9, 10])
    def test_website_flow_pays_the_creator_for_every_slot(self, w, n):
        ctx = w.start(n)
        ct, c = ctx.creators[0]
        for k in range(ds.qty(ctx.sc)):
            website_submit(w, ctx.cid, ct, k)
            w.call("POST", f"/deals/{ctx.cid}/approve", w.brand_t)         # WorkReview.js:519
        if ds.is_edit(ctx.sc):
            w.finish_edits(ctx, c)
            w.call("POST", f"/deals/{ctx.cid}/approve", w.brand_t)
        assert w.balance(c) == pytest.approx(ds.gross_each(ctx.sc) * 0.8)

    @pytest.mark.xfail(strict=False, reason=(
        "BUG (B3): the native app and pages/WorkSubmission.js post to /work/submit, which hard-codes slot 0 "
        "(server.py 10061-10062, 10098, 10122, 10128): the second call is 'Work already submitted'"))
    @pytest.mark.parametrize("n", [7, 9])
    def test_work_submit_endpoint_pays_the_creator_for_every_slot(self, w, n):
        ctx = w.start(n)
        ct, c = ctx.creators[0]
        for k in range(ds.qty(ctx.sc)):
            w.call("POST", "/work/submit", ct, json={"campaign_id": ctx.cid, "work_files": [f"https://cdn.example.com/n{k}.mp4"]})
            w.call("POST", f"/work/{w.works(ctx.cid, c)[-1]['id']}/approve", w.brand_t)
        assert w.balance(c) == pytest.approx(ds.gross_each(ctx.sc) * 0.8)

    @pytest.mark.xfail(strict=False, reason=(
        "BUG (B5, precise form): request_revision flags the newest 'submitted' content row of the creator "
        "without looking at deliverable_index (server.py 11184-11187): revising slot 2 leaves slot 2's own "
        "row 'submitted' so the resubmission is dropped"))
    def test_revision_marks_the_revised_slots_own_row(self, w):
        ctx = w.start(9)
        ct, c = ctx.creators[0]
        w.submit_all(ctx, only=c)
        last = w.works(ctx.cid, c)[-1]
        assert last["deliverable_index"] == 2
        assert w.call("POST", f"/work/{last['id']}/request-revision", w.brand_t, json={"feedback": "again"}).status_code == 200
        rows = w.run(w.db.deal_content_submissions.find({"campaign_id": ctx.cid}, {"_id": 0}).to_list(10))
        by_idx = {r["deliverable_index"]: r["status"] for r in rows}
        assert by_idx == {0: "submitted", 1: "submitted", 2: "revision_requested"}, by_idx


# ---------------------------------------------------------------------------------------------
# 3. Double click / concurrency (hire, finish hiring, approve, submit, reject)
# ---------------------------------------------------------------------------------------------
class TestDoubleClickAndRaces:
    def _one_creator_bid(self, w, n=3, factor=1.0):
        ctx = w.start(n, bid_each=False)
        ct, c = ctx.creators[0]
        w.place_bid(ctx, ct, factor=factor)
        return ctx, ct, c

    @pytest.mark.xfail(strict=False, reason=(
        "BUG (new, race): select_creator reads campaign/reservation then writes with no atomic claim (server.py 8238-8340): a double click hires the same creator twice - two held escrows, brand charged 1900 instead of 1700, second escrow can never be paid"))
    def test_double_click_hire_same_creator_charges_once(self, w, monkeypatch):
        ctx, ct, c = self._one_creator_bid(w)
        url = f"/campaigns/{ctx.cid}/select-creator?creator_id={c}"
        res = concurrently(w, monkeypatch, [("POST", url, w.brand_t, None)] * 2)
        held = [e for e in w.escrows(ctx.cid) if e["status"] == "held"]
        spent = ctx.initial - w.balance(w.brand)
        assert (len(held), spent) == (1, 1700.0), (len(held), spent, [r.status_code for r in res])
        assert sorted(r.status_code for r in res) == [200, 400]

    @pytest.mark.xfail(strict=False, reason=(
        "BUG (new, race): two concurrent hires both draw the same reservation snapshot (server.py 8262-8292); each refunds its own surplus but the pool is reduced once, so the brand wallet gains 1000 that never existed"))
    def test_two_hires_at_once_conserve_money_when_bids_are_below_the_slot(self, w, monkeypatch):
        ctx = w.start(5, bid_each=False)                                    # 3 creators wanted
        for ct, _ in ctx.creators[:2]:
            w.place_bid(ctx, ct, factor=0.5)                                # each hire frees 400 of its 1000 slot
        calls = [("POST", f"/campaigns/{ctx.cid}/select-creator?creator_id={c}", w.brand_t, None) for _, c in ctx.creators[:2]]
        res = concurrently(w, monkeypatch, calls)
        assert [r.status_code for r in res] == [200, 200], [r.text for r in res]
        view = w.money_view(ctx)
        assert view["sum"] == pytest.approx(ctx.initial), view

    @pytest.mark.xfail(strict=False, reason=(
        "BUG (new, race): finish_hiring reads the reserved pool, credits the wallet, then marks it refunded (server.py 8496-8519) with no atomic claim: two clicks credit the brand twice (+1000 minted)"))
    def test_double_click_finish_hiring_refunds_once(self, w, monkeypatch):
        ctx = w.start(5, bid_each=False)
        for ct, _ in ctx.creators[:2]:
            w.place_bid(ctx, ct)
        for _, c in ctx.creators[:2]:
            assert w.hire(ctx.cid, c).status_code == 200
        before = w.balance(w.brand)
        res = concurrently(w, monkeypatch, [("POST", f"/campaigns/{ctx.cid}/finish-hiring", w.brand_t, None)] * 2)
        assert w.balance(w.brand) - before == pytest.approx(1000.0), (w.balance(w.brand) - before, [r.status_code for r in res])
        assert sorted(r.status_code for r in res) == [200, 400]

    def test_double_click_approve_pays_once(self, w, monkeypatch):
        ctx = w.start(3)
        ct, c = ctx.creators[0]
        w.submit_all(ctx, only=c)
        res = concurrently(w, monkeypatch, [("POST", f"/deals/{ctx.cid}/approve", w.brand_t, None)] * 2)
        assert all(r.status_code == 200 for r in res), [r.text for r in res]
        assert w.balance(c) == pytest.approx(800.0)
        assert w.run(w.db.platform_revenue.count_documents({"campaign_id": ctx.cid})) == 1

    def test_double_click_approve_on_the_last_two_slots_pays_once(self, w, monkeypatch):
        ctx = w.start(9)
        ct, c = ctx.creators[0]
        w.submit_all(ctx, only=c)
        a, b, last = w.works(ctx.cid, c)
        assert w.approve_work(a["id"]).status_code == 200
        res = concurrently(w, monkeypatch, [("POST", f"/work/{x['id']}/approve", w.brand_t, None) for x in (b, last)])
        assert all(r.status_code == 200 for r in res), [r.text for r in res]
        assert w.balance(c) == pytest.approx(2400.0)
        assert w.run(w.db.platform_revenue.count_documents({"campaign_id": ctx.cid})) == 1

    @pytest.mark.xfail(strict=False, reason=(
        "BUG (new, race): submit_campaign_route checks status 'draft', then holds budget and charges the listing fee, and only flips status at the end (server.py 7201-7280): a double click charges 3000 instead of 1500 and leaves two reserved pools"))
    def test_double_click_submit_draft_holds_once(self, w, monkeypatch):
        body = w.payload(ds.SCENARIOS[3])
        body.pop("status")
        cid = w.call("POST", "/campaigns/draft", w.brand_t, json=body).json()["campaign_id"]
        before = w.balance(w.brand)
        res = concurrently(w, monkeypatch, [("POST", f"/campaigns/{cid}/submit", w.brand_t, None)] * 2)
        pools = w.run(w.db.escrow.count_documents({"campaign_id": cid}))
        assert (before - w.balance(w.brand), pools) == (1500.0, 1), (before - w.balance(w.brand), pools)
        assert sorted(r.status_code for r in res) == [200, 400]

    @pytest.mark.xfail(strict=False, reason=(
        "BUG (new, race): approve_campaign checks status then refund_campaign_reservation does find-then-credit (server.py 14099, 2586-2598): two rejects refund the hold twice (+1000 minted)"))
    def test_two_admins_rejecting_the_same_brief_refund_once(self, w, monkeypatch):
        before = w.balance(w.brand)
        cid = w.publish(ds.SCENARIOS[3]).json()["campaign_id"]
        reject = {"item_id": cid, "action": "reject", "reason": "no"}
        res = concurrently(w, monkeypatch, [("POST", "/admin/approve-campaign", w.admin_t, reject)] * 2)
        assert before - w.balance(w.brand) == pytest.approx(500.0), before - w.balance(w.brand)   # listing fee kept, hold back ONCE
        assert sorted(r.status_code for r in res) == [200, 400]


# ---------------------------------------------------------------------------------------------
# 4. Hiring on a brief an admin has frozen (B9, widened)
# ---------------------------------------------------------------------------------------------
class TestHireOnModeratedBrief:
    @pytest.mark.xfail(strict=False, reason=(
        "BUG (B9, wider than reported): select_creator has no status check (server.py 8217-8340); a BANNED brief is "
        "hired on, un-banned (status -> in_progress) and the held pool is spent"))
    @pytest.mark.parametrize("action", ["pause", "ban"])
    def test_hire_is_refused_and_status_is_kept(self, w, action):
        ctx = w.start(3, bid_each=False)
        ct, c = ctx.creators[0]
        w.place_bid(ctx, ct)
        r = w.call("POST", f"/admin/campaigns/{ctx.cid}/{action}", w.admin_t, json={"reason": "check"})
        assert r.status_code == 200, r.text
        status = w.campaign(ctx.cid)["status"]
        hire = w.hire(ctx.cid, c)
        assert hire.status_code in (400, 403, 409) and w.campaign(ctx.cid)["status"] == status, (hire.status_code, w.campaign(ctx.cid)["status"])


# ---------------------------------------------------------------------------------------------
# 5. Private brief lifecycle: decline, resubmit, revoke, expiry
# ---------------------------------------------------------------------------------------------
def private_published(w, n=1):
    ct, c = w.add_creator()
    before = w.balance(w.brand)
    cid = w.publish(ds.SCENARIOS[n], selected_creator=c, visibility="private").json()["campaign_id"]
    assert w.approve(cid).status_code == 200
    card = w.run(w.db.chat_action_cards.find_one({"type": "private_invitation", "deal_id": cid}, {"_id": 0}))
    return ct, c, cid, card, before


class TestPrivateBriefLifecycle:
    @pytest.mark.xfail(strict=False, reason=(
        "BUG: after the creator declines, the brand can re-submit the brief (status 'rejected' is allowed, it re-holds "
        "the budget and re-charges the listing fee), but deliver_private_invitation sees the OLD declined card "
        "(any status, server.py ~7360) and sends no new invitation: brand pays again for a brief nobody can see"))
    def test_resubmitted_private_brief_reaches_the_creator_again(self, w):
        ct, c, cid, card, before = private_published(w)
        assert w.call("POST", f"/chat/action-cards/{card['id']}/respond", ct,
                      json={"action": "reject", "decline_reason": server.DECLINE_REASONS[0]}).status_code == 200
        r = w.call("POST", f"/campaigns/{cid}/submit", w.brand_t)
        assert r.status_code == 200, r.text
        assert w.approve(cid).status_code == 200
        open_cards = w.run(w.db.chat_action_cards.count_documents({"deal_id": cid, "type": "private_invitation", "status": "open"}))
        assert open_cards == 1

    @pytest.mark.xfail(strict=False, reason=(
        "BUG/GAP: revoking an unanswered private invitation (POST /chat/action-cards/{id}/revoke, server.py 9401) only "
        "flips the card; the campaign stays 'active' and the budget stays 'reserved', and no brand-side route can "
        "release it"))
    def test_revoking_the_invitation_gives_the_hold_back(self, w):
        ct, c, cid, card, before = private_published(w)
        r = w.call("POST", f"/chat/action-cards/{card['id']}/revoke", w.brand_t)
        assert r.status_code == 200, r.text
        assert before - w.balance(w.brand) == pytest.approx(500.0)             # only the listing fee stays gone

    @pytest.mark.xfail(strict=False, reason=(
        "BUG/GAP: an unanswered private invitation expires only lazily when someone tries to answer it (server.py 9280); "
        "no sweep refunds the hold, so the brand's money sits 'reserved' on a dead brief until an admin steps in"))
    def test_expired_invitation_releases_the_hold(self, w):
        ct, c, cid, card, before = private_published(w)
        past = "2020-01-01T00:00:00+00:00"
        w.run(w.db.chat_action_cards.update_one({"id": card["id"]}, {"$set": {"fields.response_deadline": past, "created_at": past}}))
        r = w.call("POST", f"/chat/action-cards/{card['id']}/respond", ct, json={"action": "accept"})
        assert r.status_code == 400 and "expired" in r.text
        assert before - w.balance(w.brand) == pytest.approx(500.0)


# ---------------------------------------------------------------------------------------------
# 6. Revision loops and wallet limits (scenario 3 and 9)
# ---------------------------------------------------------------------------------------------
class TestRevisionLoops:
    def _revise(self, w, ctx, ct):
        wk = w.works(ctx.cid, ctx.creators[0][1], status="submitted")[0]
        return w.call("POST", f"/work/{wk['id']}/request-revision", w.brand_t, json={"feedback": "Please redo the hook"})

    def test_three_rounds_two_free_one_paid_and_the_money_adds_up(self, w):
        ctx = w.start(3)
        ct, c = ctx.creators[0]
        w.submit(ctx.cid, ct, 0)
        fees = []
        for i in range(3):
            r = self._revise(w, ctx, ct)
            assert r.status_code == 200, r.text
            fees.append(r.json()["fee_charged"])
            assert w.submit(ctx.cid, ct, 0).json()["version"] == i + 2
        assert fees == [0, 0, 500]
        before_brand = w.balance(w.brand)
        w.approve_pending(ctx, c)
        assert w.balance(c) == pytest.approx(800.0 + 300.0)                    # 80% + the creator's share of the paid round
        assert ctx.initial - before_brand == pytest.approx(1200.0 + 500.0 + 500.0)
        assert [e["status"] for e in w.escrows(ctx.cid)] == ["released"]

    def test_sixth_round_is_refused_and_five_is_the_cap(self, w):
        ctx = w.start(3)
        ct, c = ctx.creators[0]
        w.submit(ctx.cid, ct, 0)
        for i in range(5):
            assert self._revise(w, ctx, ct).status_code == 200
            assert w.submit(ctx.cid, ct, 0).status_code == 200
        r = self._revise(w, ctx, ct)
        assert r.status_code == 400 and "5-revision" in r.text

    def test_paid_round_with_empty_wallet_is_refused_and_changes_nothing(self, w):
        ctx = w.start(3)
        ct, c = ctx.creators[0]
        w.submit(ctx.cid, ct, 0)
        for _ in range(2):
            assert self._revise(w, ctx, ct).status_code == 200
            w.submit(ctx.cid, ct, 0)
        w.set_balance(w.brand, 100.0)
        r = self._revise(w, ctx, ct)
        assert r.status_code == 402
        assert w.works(ctx.cid, c, status="submitted") and w.balance(w.brand) == 100.0

    @pytest.mark.xfail(strict=False, reason=(
        "BUG/POLICY (legal text 8.2: each slot has its own revision allowance): revisions are counted per DEAL "
        "(deal_revision_history, server.py 11135), so in a qty-3 brief slot 3 is charged Rs 500 on its first revision "
        "after two free rounds were spent on other slots"))
    def test_free_revisions_are_per_slot(self, w):
        ctx = w.start(9)
        ct, c = ctx.creators[0]
        w.submit_all(ctx, only=c)
        works = w.works(ctx.cid, c)
        for wk in works[:2]:
            assert w.call("POST", f"/work/{wk['id']}/request-revision", w.brand_t, json={"feedback": "x"}).json()["fee_charged"] == 0
        third = w.call("POST", f"/work/{works[2]['id']}/request-revision", w.brand_t, json={"feedback": "x"})
        assert third.json()["fee_charged"] == 0


# ---------------------------------------------------------------------------------------------
# 7. A hired creator drops out; refund of a held deal
# ---------------------------------------------------------------------------------------------
class TestCreatorDropsOut:
    def test_one_ghosting_creator_does_not_block_the_others_payouts(self, w):
        ctx = w.start(5)
        (a_t, a), (b_t, b), (c_t, c3) = ctx.creators
        for ct, cid in ((b_t, b), (c_t, c3)):
            w.submit(ctx.cid, ct, 0)
        w.approve_pending(ctx)
        assert w.balance(b) == pytest.approx(800.0) and w.balance(c3) == pytest.approx(800.0) and w.balance(a) == 0
        assert w.campaign(ctx.cid)["status"] != "completed"

    @pytest.mark.xfail(strict=False, reason=(
        "BUG/POLICY: admin_refund_escrow (server.py 18064) refunds escrow.amount only. The brand was charged amount + 20% "
        "(brand_charged); the 20% fee is neither returned nor booked as revenue, it just disappears from the books"))
    def test_refunding_a_ghosted_deal_returns_everything_the_brand_paid(self, w):
        ctx = w.start(3)
        before = w.balance(w.brand)
        r = w.call("POST", f"/admin/deals/{ctx.cid}/refund", w.admin_t, json={"reason": "creator never delivered"})
        assert r.status_code == 200, r.text
        assert w.balance(w.brand) - before == pytest.approx(1200.0)

    def test_refunding_one_creators_deal_leaves_the_other_creators_deals_intact(self, w):
        ctx = w.start(5)
        (a_t, a), (b_t, b), _ = ctx.creators
        r = w.call("POST", f"/admin/deals/{ctx.cid}/refund", w.admin_t, json={"creator_id": a, "reason": "ghosted"})
        assert r.status_code == 200, r.text
        status = {e["creator_id"]: e["status"] for e in w.escrows(ctx.cid)}
        assert status[a] == "refunded" and status[b] == "held"
        w.submit(ctx.cid, b_t, 0)
        w.approve_pending(ctx, b)
        assert w.balance(b) == pytest.approx(800.0)


# ---------------------------------------------------------------------------------------------
# 8. Odd budgets with TDS switched ON (the junior ran with TDS off)
# ---------------------------------------------------------------------------------------------
class TestOddBudgetsWithTds:
    @pytest.mark.parametrize("per_video", [333.33, 1234.56, 17.5, 250.25])
    @pytest.mark.parametrize("n", [3, 9, 5])
    def test_money_is_conserved_with_tds_on(self, monkeypatch, per_video, n):
        monkeypatch.setenv("TDS_WITHHOLDING_ENABLED", "true")
        monkeypatch.setitem(vars(ds), "PER_VIDEO", per_video)
        world = ds.World(monkeypatch)
        try:
            ctx = world.start(n)
            world.submit_all(ctx)
            world.approve_pending(ctx)
            view = world.money_view(ctx)
            gross = per_video * ds.qty(ctx.sc)
            assert view["in_escrow"] == 0
            assert view["sum"] == pytest.approx(ctx.initial, abs=0.01), view
            for _, c in ctx.creators:
                assert world.balance(c) == pytest.approx(gross - round(gross * 0.2, 2) - round(gross * 0.1, 2), abs=0.02)
        finally:
            world.close()


class TestPatchedPrivateDraft:
    def test_invitation_card_shows_the_same_price_the_pool_holds(self, w):
        """B7 follow-up: after PATCH re-prices a private draft, the creator is shown the PATCHED price
        (the junior report said the card shows the real one). Pins the card against the hold."""
        ct, c = w.add_creator()
        body = w.payload(ds.SCENARIOS[1], selected_creator=c, visibility="private")
        body.pop("status")
        cid = w.call("POST", "/campaigns/draft", w.brand_t, json=body).json()["campaign_id"]
        w.call("PATCH", f"/campaigns/{cid}", w.brand_t, json={"per_video_budget": 1, "budget_min": 1, "budget_max": 1})
        assert w.call("POST", f"/campaigns/{cid}/submit", w.brand_t).status_code == 200
        assert w.approve(cid).status_code == 200
        card = w.run(w.db.chat_action_cards.find_one({"type": "private_invitation", "deal_id": cid}, {"_id": 0}))
        [pool] = w.escrows(cid)
        assert card["fields"]["budget"] == pool["amount"] == 1.0          # creator sees and is held at Rs 1, not the rate card's 1000
