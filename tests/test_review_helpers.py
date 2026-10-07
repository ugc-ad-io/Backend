import asyncio
from types import SimpleNamespace
from unittest.mock import Mock

from review_helpers import received_review_query, review_summary


def test_creator_reviews_exclude_reviews_written_about_brands():
    assert received_review_query({"id": "creator", "role": "creator"}) == {
        "creator_id": "creator", "reviewee_role": {"$ne": "business"},
    }


def test_brand_team_member_receives_workspace_reviews():
    assert received_review_query({"id": "member", "role": "business", "team_of": "owner"}) == {
        "business_id": "owner", "reviewee_role": "business",
    }


def test_summary_uses_received_reviews_instead_of_null_cached_rating():
    async def to_list(limit):
        return [{"average": 4.666666, "count": 3}]
    collection = Mock()
    collection.aggregate.return_value = SimpleNamespace(to_list=to_list)
    user = {"id": "creator", "role": "creator", "average_rating": None}
    summary = asyncio.run(review_summary(SimpleNamespace(reviews=collection), user))
    assert summary == {"average_rating": 4.67, "avg_rating": 4.67,
                       "total_reviews": 3, "review_count": 3}
    assert collection.aggregate.call_args.args[0][0] == {"$match": received_review_query(user)}


def test_no_reviews_returns_numbers_instead_of_null():
    async def to_list(limit):
        return []
    collection = Mock()
    collection.aggregate.return_value = SimpleNamespace(to_list=to_list)
    summary = asyncio.run(review_summary(SimpleNamespace(reviews=collection), {"id": "brand", "role": "business"}))
    assert summary == {"average_rating": 0, "avg_rating": 0, "total_reviews": 0, "review_count": 0}
