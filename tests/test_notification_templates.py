"""Admin-editable notification/email wording: defaults stay identical, overrides win,
bad placeholders are rejected, reset returns to the default."""
import re

import pytest
from fastapi import HTTPException

pytest.importorskip("mongomock_motor")

from mongomock_motor import AsyncMongoMockClient  # noqa: E402

import server  # noqa: E402

ADMIN = {"id": "admin-1", "role": "admin", "nickname": "Ops"}


@pytest.fixture
def sent(monkeypatch):
    monkeypatch.setattr(server, "db", AsyncMongoMockClient()["notif_templates"])
    calls = []

    async def fake_notify(user_id, title, message, **kw):
        calls.append({"user_id": user_id, "title": title, "message": message, **kw})

    monkeypatch.setattr(server, "notify_user", fake_notify)
    return calls


def test_every_default_only_uses_its_declared_placeholders():
    for key, ev in server.NOTIF_EVENTS.items():
        used = set(re.findall(r"\{(\w+)\}", ev["title"] + ev["message"]))
        assert used <= set(ev["vars"]), f"{key}: {used - set(ev['vars'])}"


@pytest.mark.asyncio
async def test_default_wording_is_unchanged_and_email_follows_the_registry(sent):
    await server.notify_event("creator-1", "payment_released", {"amount": 500}, link="/withdrawal")
    c = sent[0]
    assert c["title"] == "Payment released"
    assert c["message"] == "₹500 has been released to your wallet."
    assert c["email"] is True and c["email_subject"] is None
    await server.notify_event("creator-1", "content_approved")
    assert sent[1]["message"] == "Your content was approved."


@pytest.mark.asyncio
async def test_admin_edit_changes_notification_and_email_then_reset(sent):
    saved = await server.admin_save_notification_template(
        "payment_released",
        server.NotifTemplateUpdate(title="Money is in!", message="Rs {amount} landed in your wallet.",
                                   email_subject="Your payout", email_body="Hi,\nRs {amount} is yours.",
                                   email_enabled=False),
        ADMIN)
    assert saved["override"]["title"] == "Money is in!"
    await server.notify_event("creator-1", "payment_released", {"amount": "<b>9</b>"})
    c = sent[-1]
    assert c["title"] == "Money is in!" and c["message"] == "Rs <b>9</b> landed in your wallet."
    assert c["email"] is False
    assert c["email_subject"] == "Your payout"
    assert c["email_html"] == "Hi,<br>Rs &lt;b&gt;9&lt;/b&gt; is yours."   # values escaped, text kept

    await server.admin_reset_notification_template("payment_released", ADMIN)
    await server.notify_event("creator-1", "payment_released", {"amount": 1})
    assert sent[-1]["title"] == "Payment released" and sent[-1]["email"] is True


@pytest.mark.asyncio
async def test_unknown_placeholder_and_unknown_event_are_rejected(sent):
    with pytest.raises(HTTPException) as e:
        await server.admin_save_notification_template(
            "payment_released", server.NotifTemplateUpdate(message="Hi {brand_name}"), ADMIN)
    assert e.value.status_code == 400 and "{brand_name}" in e.value.detail
    with pytest.raises(HTTPException) as e:
        await server.admin_save_notification_template("nope", server.NotifTemplateUpdate(title="x"), ADMIN)
    assert e.value.status_code == 404


@pytest.mark.asyncio
async def test_saving_the_defaults_back_removes_the_override(sent):
    await server.admin_save_notification_template(
        "content_approved", server.NotifTemplateUpdate(title="Nice work"), ADMIN)
    out = await server.admin_save_notification_template(
        "content_approved", server.NotifTemplateUpdate(title="", message="", email_enabled=True), ADMIN)
    assert out["override"] is None
    listing = await server.admin_list_notification_templates(ADMIN)
    row = next(r for r in listing["events"] if r["key"] == "content_approved")
    assert row["override"] is None
