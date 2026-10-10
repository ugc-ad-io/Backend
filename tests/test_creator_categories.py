import server


def test_creator_listed_under_every_category_they_picked():
    creator = {"profile": {"primary_category": "fashion",
                           "content_categories": ["fashion", "Beauty", "home"],
                           "contentCategories": ["beauty", "food"]}}
    assert server.creator_categories(creator, "fashion") == ["fashion", "Beauty", "home", "food"]
    for category in ("fashion", "beauty", "home", "food"):
        assert server.creator_matches_directory_filters(creator, category, None, None, None, None)
    assert not server.creator_matches_directory_filters(creator, "tech", None, None, None, None)
    assert server.creator_directory_public_view(creator, 0)["categories"] == ["fashion", "Beauty", "home", "food"]
