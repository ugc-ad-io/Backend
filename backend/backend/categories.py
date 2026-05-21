"""
Categories management module for UGCad platform.
Provides endpoints for retrieving content categories used in filtering.
"""

from fastapi import APIRouter
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel
from typing import List
import os

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

categories_router = APIRouter(prefix="/api")

# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class Category(BaseModel):
    id: str
    name: str
    description: str
    icon: str
    active: bool
    order: int

    class Config:
        json_schema_extra = {
            "example": {
                "id": "ugc-videos",
                "name": "UGC Videos",
                "description": "Original user-generated video content",
                "icon": "video-camera",
                "active": True,
                "order": 1
            }
        }

# ============================================================================
# SAMPLE CATEGORIES DATA
# ============================================================================

SAMPLE_CATEGORIES = [
    {
        "id": "ugc-videos",
        "name": "UGC Videos",
        "description": "Original user-generated video content",
        "icon": "video-camera",
        "active": True,
        "order": 1
    },
    {
        "id": "product-reviews",
        "name": "Product Reviews",
        "description": "Detailed reviews and honest opinions on products",
        "icon": "star-review",
        "active": True,
        "order": 2
    },
    {
        "id": "unboxing",
        "name": "Unboxing",
        "description": "Unboxing and first impressions of products",
        "icon": "package-open",
        "active": True,
        "order": 3
    },
    {
        "id": "testimonials",
        "name": "Testimonials",
        "description": "Customer testimonials and success stories",
        "icon": "message-quote",
        "active": True,
        "order": 4
    },
    {
        "id": "demo-videos",
        "name": "Demo Videos",
        "description": "Product demonstrations and how-to videos",
        "icon": "play-circle",
        "active": True,
        "order": 5
    },
    {
        "id": "social-media-content",
        "name": "Social Media Content",
        "description": "Short-form content for Instagram, TikTok, Reels",
        "icon": "share-2",
        "active": True,
        "order": 6
    },
    {
        "id": "lifestyle-content",
        "name": "Lifestyle Content",
        "description": "Lifestyle and day-in-the-life content featuring products",
        "icon": "heart",
        "active": True,
        "order": 7
    },
    {
        "id": "product-comparison",
        "name": "Product Comparison",
        "description": "Side-by-side comparisons of products or alternatives",
        "icon": "scale",
        "active": True,
        "order": 8
    },
    {
        "id": "tutorials",
        "name": "Tutorials",
        "description": "Step-by-step guides and tutorial content",
        "icon": "book-open",
        "active": True,
        "order": 9
    },
    {
        "id": "behind-the-scenes",
        "name": "Behind the Scenes",
        "description": "Behind-the-scenes and creator workspace content",
        "icon": "camera",
        "active": True,
        "order": 10
    }
]

# ============================================================================
# ENDPOINTS
# ============================================================================

@categories_router.get("/categories", response_model=List[Category])
async def get_categories():
    """
    Get all active categories for content filtering.

    Returns:
        List[Category]: Array of category objects sorted by order.

    Example:
        GET /api/categories

        Response:
        [
            {
                "id": "ugc-videos",
                "name": "UGC Videos",
                "description": "Original user-generated video content",
                "icon": "video-camera",
                "active": true,
                "order": 1
            },
            ...
        ]
    """
    categories = await db.categories.find(
        {"active": True},
        {"_id": 0}
    ).sort("order", 1).to_list(None)

    return categories

# ============================================================================
# ADMIN ENDPOINTS (for managing categories)
# ============================================================================

@categories_router.get("/admin/categories", tags=["admin"])
async def get_all_categories_admin():
    """
    Get all categories (including inactive ones) - Admin only.
    Used for admin panel to manage categories.
    """
    categories = await db.categories.find(
        {},
        {"_id": 0}
    ).sort("order", 1).to_list(None)

    return categories

# ============================================================================
# INITIALIZATION HELPER
# ============================================================================

async def seed_categories():
    """
    Seed the categories collection with default categories if empty.
    Call this from server.py startup event.
    """
    count = await db.categories.count_documents({})

    if count == 0:
        await db.categories.insert_many(SAMPLE_CATEGORIES)
        print(f"[INIT] Seeded {len(SAMPLE_CATEGORIES)} categories to db.categories")
    else:
        print(f"[INIT] Categories collection already has {count} documents")
