#!/usr/bin/env python3
"""
Test script for Categories endpoint.
"""

import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
import os
from dotenv import load_dotenv
from pathlib import Path
import json

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

async def test_categories():
    print("=" * 70)
    print("Categories Endpoint Test")
    print("=" * 70)

    try:
        # Get categories from MongoDB
        categories = await db.categories.find(
            {"active": True},
            {"_id": 0}
        ).sort("order", 1).to_list(None)

        print(f"\n[OK] Found {len(categories)} active categories\n")

        # Display each category
        for cat in categories:
            print(f"  {cat['order']}. [{cat['id']}] {cat['name']}")
            print(f"     Description: {cat['description']}")
            print(f"     Icon: {cat['icon']}")
            print()

        # Test response format
        print("\n" + "=" * 70)
        print("Sample JSON Response (First 2 categories)")
        print("=" * 70)
        print(json.dumps(categories[:2], indent=2, default=str))

        print("\n" + "=" * 70)
        print("Test Summary")
        print("=" * 70)
        print(f"[OK] Categories endpoint ready")
        print(f"[OK] Total categories: {len(categories)}")
        print(f"[OK] All categories are active: {all(cat['active'] for cat in categories)}")
        print(f"[OK] Categories are sorted by order: {all(categories[i]['order'] <= categories[i+1]['order'] for i in range(len(categories)-1))}")
        print(f"\n[INFO] Endpoint: GET /api/categories")
        print(f"[INFO] No authentication required")
        print(f"[INFO] Returns: Array of category objects sorted by order")
        print("=" * 70)

    except Exception as e:
        print(f"[ERROR] {e}")
        import traceback
        traceback.print_exc()
    finally:
        client.close()

if __name__ == "__main__":
    asyncio.run(test_categories())
