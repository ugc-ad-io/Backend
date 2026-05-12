import pytest
from fastapi import HTTPException

import server


class FakeCursor:
    def __init__(self, docs):
        self.docs = docs

    def sort(self, *_args):
        return self

    async def to_list(self, _limit):
        return [doc.copy() for doc in self.docs]


def get_value(doc, path):
    value = doc
    for part in path.split("."):
        if isinstance(value, list):
            return any(get_value(item, ".".join(path.split(".")[path.split(".").index(part):])) for item in value)
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def matches(doc, query):
    for key, expected in query.items():
        if key == "$or":
            if not any(matches(doc, item) for item in expected):
                return False
            continue
        actual = get_value(doc, key)
        if isinstance(expected, dict):
            if "$ne" in expected and actual == expected["$ne"]:
                return False
            if "$in" in expected and actual not in expected["$in"]:
                return False
            if "$nin" in expected and actual in expected["$nin"]:
                return False
            if "$gt" in expected and not (actual and actual > expected["$gt"]):
                return False
            if "$gte" in expected and not (actual and actual >= expected["$gte"]):
                return False
            if "$all" in expected and not all(item in (actual or []) for item in expected["$all"]):
                return False
            continue
        if actual != expected:
            return False
    return True


class FakeCollection:
    def __init__(self, docs=None):
        self.docs = docs or []

    async def find_one(self, query, *_args, **_kwargs):
        return next((doc.copy() for doc in self.docs if matches(doc, query)), None)

    def find(self, query=None, *_args, **_kwargs):
        query = query or {}
        return FakeCursor([doc for doc in self.docs if matches(doc, query)])

    async def insert_one(self, doc):
        self.docs.append(doc.copy())

    async def count_documents(self, query):
        return len([doc for doc in self.docs if matches(doc, query)])

    async def update_one(self, query, update, **_kwargs):
        doc = next((item for item in self.docs if matches(item, query)), None)
        if not doc:
            doc = query.copy()
            self.docs.append(doc)
        apply_update(doc, update)

    async def update_many(self, query, update, **_kwargs):
        for doc in self.docs:
            if matches(doc, query):
                apply_update(doc, update)


def apply_update(doc, update):
    for key, value in update.get("$set", {}).items():
        doc[key] = value
    for key, value in update.get("$addToSet", {}).items():
        doc.setdefault(key, [])
        if value not in doc[key]:
            doc[key].append(value)
    for key in update.get("$unset", {}):
        doc.pop(key, None)


class FakeDB:
    def __init__(self):
        self.users = FakeCollection()
        self.campaigns = FakeCollection()
        self.messages = FakeCollection()
        self.chat_action_cards = FakeCollection()
        self.uploaded_files = FakeCollection()
        self.violations = FakeCollection()
        self.chat_strikes = FakeCollection()
        self.chat_pauses = FakeCollection()
        self.in_app_notifications = FakeCollection()
        self.admin_notifications = FakeCollection()
        self.chat_false_positive_reviews = FakeCollection()
        self.chat_typing = FakeCollection()
        self.escrow = FakeCollection()

    def __getitem__(self, name):
        if not hasattr(self, name):
            setattr(self, name, FakeCollection())
        return getattr(self, name)


@pytest.fixture()
def fake_db(monkeypatch):
    db = FakeDB()
    monkeypatch.setattr(server, "db", db)
    return db


def business(balance=6000, approval_status="approved"):
    return {"id": "brand-1", "nickname": "Brand", "role": "business", "approval_status": approval_status, "balance": balance}


def creator():
    return {"id": "creator-1", "nickname": "Creator", "role": "creator", "approval_status": "approved", "balance": 0}


@pytest.mark.asyncio
async def test_text_message_send(fake_db):
    fake_db.users.docs = [business(), creator()]
    payload = server.ChatMessage(recipient_id="creator-1", message="Hello", attachment_urls=[])
    await server.send_message(payload, business())
    assert fake_db.messages.docs[0]["message"] == "Hello"


@pytest.mark.asyncio
async def test_attachment_only_message_send(fake_db):
    fake_db.users.docs = [business(), creator()]
    fake_db.uploaded_files.docs = [{"file_url": "/uploads/a.png", "filename": "a.png", "content_type": "image/png", "size": 100, "kind": "image"}]
    payload = server.ChatMessage(recipient_id="creator-1", message="", attachment_urls=["/uploads/a.png"])
    await server.send_message(payload, business())
    assert fake_db.messages.docs[0]["attachment_urls"] == ["/uploads/a.png"]


@pytest.mark.asyncio
async def test_blocked_contact_info_message_logs_strike(fake_db):
    fake_db.users.docs = [business(), creator()]
    payload = server.ChatMessage(recipient_id="creator-1", message="Call 98765 43210", attachment_urls=[])
    with pytest.raises(HTTPException) as exc:
        await server.send_message(payload, business())
    assert exc.value.status_code == 400
    assert fake_db.messages.docs == []
    assert len(fake_db.violations.docs) == 1
    assert len(fake_db.chat_strikes.docs) == 1


@pytest.mark.asyncio
async def test_strike_progression_sets_action_cards_only(fake_db):
    fake_db.users.docs = [business()]
    for _ in range(3):
        await server.log_chat_violation(business(), "creator-1", "wa.me/abc", [{"type": "contact_link", "severity": "high"}])
    assert fake_db.users.docs[0].get("action_cards_only_until")


@pytest.mark.asyncio
async def test_brand_wallet_gate(fake_db):
    fake_db.users.docs = [business(balance=100), creator()]
    with pytest.raises(HTTPException) as exc:
        await server.validate_chat_access(business(balance=100), "creator-1")
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_creator_relationship_gate(fake_db):
    fake_db.users.docs = [business(), creator()]
    with pytest.raises(HTTPException):
        await server.validate_chat_access(creator(), "brand-1")
    fake_db.campaigns.docs = [{"id": "campaign-1", "business_id": "brand-1", "selected_creator": "creator-1", "status": "in_progress"}]
    recipient = await server.validate_chat_access(creator(), "brand-1")
    assert recipient["id"] == "brand-1"


@pytest.mark.asyncio
async def test_action_card_creation_and_immutability(fake_db):
    fake_db.users.docs = [business(), creator()]
    data = server.ChatActionCardCreate(
        recipient_id="creator-1",
        type="custom_offer",
        fields={"deliverable_type": "video", "quantity": 1, "duration": "30s", "price": 12000, "timeline": "7 days", "usage_rights": "organic"},
    )
    await server.create_chat_action_card(data, business())
    original_fields = fake_db.chat_action_cards.docs[0]["fields"].copy()
    await server.respond_chat_action_card(fake_db.chat_action_cards.docs[0]["id"], server.ChatActionCardRespond(action="accept"), creator())
    assert fake_db.chat_action_cards.docs[0]["fields"] == original_fields


@pytest.mark.asyncio
async def test_chat_history_returns_messages_and_action_cards(fake_db):
    fake_db.users.docs = [business(), creator()]
    fake_db.campaigns.docs = [{"id": "campaign-1", "business_id": "brand-1", "selected_creator": "creator-1", "status": "in_progress"}]
    fake_db.messages.docs = [{"id": "m1", "sender_id": "brand-1", "recipient_id": "creator-1", "message": "Hi", "timestamp": "2026-01-01T00:00:00+00:00", "read": False}]
    fake_db.chat_action_cards.docs = [{"id": "c1", "participants": ["brand-1", "creator-1"], "sender_id": "brand-1", "recipient_id": "creator-1", "type": "milestone_update", "fields": {"status": "sent"}, "status": "open", "created_at": "2026-01-01T00:01:00+00:00", "read_by": []}]
    items = await server.get_chat_history("brand-1", creator())
    assert [item["item_type"] for item in items] == ["message", "action_card"]


def test_attachment_validation_rejects_unsupported_file():
    with pytest.raises(HTTPException):
        server.validate_upload_payload("application/x-msdownload", "run.exe", 100)
