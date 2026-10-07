"""Shared received-review queries and rating summaries for web and mobile APIs."""


def received_review_query(user):
    if user.get("role") == "business":
        return {
            "business_id": user.get("team_of") or user["id"],
            "reviewee_role": "business",
        }
    return {"creator_id": user["id"], "reviewee_role": {"$ne": "business"}}


async def review_summary(db, user):
    rows = await db.reviews.aggregate([
        {"$match": received_review_query(user)},
        {"$group": {"_id": None, "average": {"$avg": "$rating"}, "count": {"$sum": 1}}},
    ]).to_list(1)
    row = rows[0] if rows else {}
    average = round(row.get("average") or 0, 2)
    count = row.get("count", 0)
    return {"average_rating": average, "avg_rating": average,
            "total_reviews": count, "review_count": count}
