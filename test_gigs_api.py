"""
Test script for Gigs API endpoints.
Tests all gig approval system endpoints.
"""

import httpx
import asyncio
import json
from datetime import datetime, timezone, timedelta

BASE_URL = "http://localhost:5000/api"

# Test data
TEST_CREATOR_ID = "test-creator-001"
TEST_ADMIN_ID = "test-admin-001"
TEST_CREATOR_TOKEN = "test-creator-token"  # Replace with actual token
TEST_ADMIN_TOKEN = "test-admin-token"  # Replace with actual token

async def test_create_gig():
    """Test creating a new gig"""
    print("\n📝 Testing: Create Gig (POST /api/gigs)")
    print("=" * 60)

    gig_data = {
        "title": "Create Instagram Reels",
        "description": "Create engaging Instagram reels for our fashion brand. Must include product shots and trending music.",
        "category": "social_media",
        "budget": 500.00,
        "deadline": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
        "attachments": ["https://example.com/image1.jpg", "https://example.com/image2.jpg"],
        "requirements": "Must include product shots and trending music",
        "target_audience": "Women 18-35",
        "skills_required": ["Video Editing", "Creative Content"]
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{BASE_URL}/gigs",
            json=gig_data,
            headers={"Authorization": f"Bearer {TEST_CREATOR_TOKEN}"}
        )

        print(f"Status Code: {response.status_code}")
        if response.status_code == 201:
            data = response.json()
            print("✅ Gig created successfully")
            print(f"Gig ID: {data.get('id')}")
            print(f"Status: {data.get('status')}")
            return data.get('id')
        else:
            print(f"❌ Failed to create gig: {response.text}")
            return None

async def test_list_gigs():
    """Test listing gigs with filters"""
    print("\n📋 Testing: List Gigs (GET /api/gigs)")
    print("=" * 60)

    async with httpx.AsyncClient() as client:
        # List all gigs
        response = await client.get(f"{BASE_URL}/gigs?page=1&limit=10")
        print(f"Status Code: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            print(f"✅ Retrieved {len(data.get('data', []))} gigs")
            print(f"Total gigs: {data.get('pagination', {}).get('total')}")
        else:
            print(f"❌ Failed to list gigs: {response.text}")

        # List with filters
        response = await client.get(f"{BASE_URL}/gigs?status=pending_approval&category=social_media&page=1&limit=5")
        print(f"\nFiltered (pending_approval, social_media):")
        print(f"Status Code: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            print(f"✅ Retrieved {len(data.get('data', []))} filtered gigs")
        else:
            print(f"❌ Failed to list filtered gigs: {response.text}")

async def test_get_single_gig(gig_id: str):
    """Test getting a single gig"""
    if not gig_id:
        print("\n⏭️  Skipping: Get Single Gig (no gig_id available)")
        return

    print("\n🔍 Testing: Get Single Gig (GET /api/gigs/{id})")
    print("=" * 60)

    async with httpx.AsyncClient() as client:
        response = await client.get(f"{BASE_URL}/gigs/{gig_id}")

        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print("✅ Gig retrieved successfully")
            print(f"Title: {data.get('title')}")
            print(f"Budget: ${data.get('budget')}")
            print(f"Status: {data.get('status')}")
        else:
            print(f"❌ Failed to get gig: {response.text}")

async def test_approve_gig(gig_id: str):
    """Test approving a gig (admin only)"""
    if not gig_id:
        print("\n⏭️  Skipping: Approve Gig (no gig_id available)")
        return

    print("\n✅ Testing: Approve Gig (PATCH /api/gigs/{id}?action=approve)")
    print("=" * 60)

    approval_data = {
        "status": "approved",
        "notes": "Looks good! Proceed with this gig."
    }

    async with httpx.AsyncClient() as client:
        response = await client.patch(
            f"{BASE_URL}/gigs/{gig_id}?action=approve",
            json=approval_data,
            headers={"Authorization": f"Bearer {TEST_ADMIN_TOKEN}"}
        )

        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print("✅ Gig approved successfully")
            print(f"Status: {data.get('data', {}).get('status')}")
        else:
            print(f"❌ Failed to approve gig: {response.text}")

async def test_reject_gig(gig_id: str):
    """Test rejecting a gig (admin only)"""
    if not gig_id:
        print("\n⏭️  Skipping: Reject Gig (no gig_id available)")
        return

    print("\n❌ Testing: Reject Gig (PATCH /api/gigs/{id}?action=reject)")
    print("=" * 60)

    rejection_data = {
        "status": "rejected",
        "rejection_reason": "Budget exceeds our current budget constraints for this category"
    }

    async with httpx.AsyncClient() as client:
        response = await client.patch(
            f"{BASE_URL}/gigs/{gig_id}?action=reject",
            json=rejection_data,
            headers={"Authorization": f"Bearer {TEST_ADMIN_TOKEN}"}
        )

        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print("✅ Gig rejected successfully")
            print(f"Rejection Reason: {data.get('data', {}).get('rejection_reason')}")
        else:
            print(f"❌ Failed to reject gig: {response.text}")

async def test_get_creator_gigs(creator_id: str = TEST_CREATOR_ID):
    """Test getting gigs by a specific creator"""
    print("\n👤 Testing: Get Creator's Gigs (GET /api/gigs/creator/{creator_id})")
    print("=" * 60)

    async with httpx.AsyncClient() as client:
        response = await client.get(f"{BASE_URL}/gigs/creator/{creator_id}?page=1&limit=10")

        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Retrieved {len(data.get('data', []))} gigs for creator")
            print(f"Total: {data.get('pagination', {}).get('total')}")
        else:
            print(f"❌ Failed to get creator gigs: {response.text}")

async def test_error_cases():
    """Test error handling"""
    print("\n⚠️  Testing: Error Cases")
    print("=" * 60)

    async with httpx.AsyncClient() as client:
        # Test 404 - Non-existent gig
        print("\nTest 1: Get non-existent gig (should return 404)")
        response = await client.get(f"{BASE_URL}/gigs/nonexistent-gig-id")
        print(f"Status Code: {response.status_code}")
        if response.status_code == 404:
            print("✅ Correctly returned 404")

        # Test missing authorization
        print("\nTest 2: Create gig without authorization (should return 401)")
        gig_data = {
            "title": "Test",
            "description": "Test description for testing purposes",
            "category": "social_media",
            "budget": 100,
            "deadline": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        }
        response = await client.post(f"{BASE_URL}/gigs", json=gig_data)
        print(f"Status Code: {response.status_code}")
        if response.status_code == 403 or response.status_code == 401:
            print("✅ Correctly returned auth error")

async def run_all_tests():
    """Run all tests"""
    print("🚀 Starting Gigs API Tests")
    print("=" * 60)

    # Create a gig
    gig_id = await test_create_gig()

    # List gigs
    await test_list_gigs()

    # Get single gig
    await test_get_single_gig(gig_id)

    # Test creator gigs
    await test_get_creator_gigs()

    # Approve gig
    await test_approve_gig(gig_id)

    # Test error cases
    await test_error_cases()

    print("\n" + "=" * 60)
    print("✅ All tests completed!")
    print("=" * 60)

if __name__ == "__main__":
    print("""
    ⚠️  NOTE: Make sure to:
    1. Update TEST_CREATOR_TOKEN and TEST_ADMIN_TOKEN with real tokens
    2. Ensure the backend server is running on http://localhost:5000
    3. Have valid creator and admin users in the database
    """)

    asyncio.run(run_all_tests())
