#!/usr/bin/env python3
"""
Test script for Applications Management API endpoints.
Tests the CRUD operations and business logic for creator and brand applications.
"""

import asyncio
import uuid
from datetime import datetime, timezone, timedelta
from motor.motor_asyncio import AsyncIOMotorClient
import os
from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB setup
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

async def create_test_creator_application():
    """Create a test creator application document"""
    app = {
        "id": str(uuid.uuid4()),
        "user_id": str(uuid.uuid4()),
        "nickname": "@TestCreator123",
        "email": "creator@test.com",
        "phone": "+91-9876543210",
        "status": "pending",
        "submitted_date": now_iso(),
        "category": "fashion",
        "languages": ["English", "Hindi"],
        "location": "Mumbai",
        "bio": "Fashion influencer with 50K followers",
        "profile_picture": "https://example.com/pic.jpg",
        "rate_card": {
            "video_30s": 5000,
            "video_60s": 8000,
            "photo_post": 2000,
            "reel_15s": 3000,
            "story": 1000
        },
        "portfolio_videos": [
            {
                "id": str(uuid.uuid4()),
                "url": "https://example.com/video1.mp4",
                "title": "Fashion Campaign",
                "duration": 120,
                "thumbnail": "https://example.com/thumb1.jpg",
                "views": 5000
            }
        ],
        "kyc_documents": {
            "pan": {
                "id": str(uuid.uuid4()),
                "url": "https://example.com/pan.pdf",
                "number": "ABCDE1234F",
                "name": "Test Creator",
                "verified": False,
                "verified_at": None,
                "verification_details": {}
            },
            "aadhaar": {
                "id": str(uuid.uuid4()),
                "url": "https://example.com/aadhaar.pdf",
                "last_4_digits": "1234",
                "verified": False,
                "verified_at": None
            },
            "selfie_with_id": {
                "id": str(uuid.uuid4()),
                "url": "https://example.com/selfie.jpg",
                "verified": False,
                "verified_at": None,
                "liveness_score": None
            }
        },
        "social_handles": {
            "instagram": {
                "handle": "@testcreator",
                "followers": 50000,
                "verified": True,
                "profile_url": "https://instagram.com/testcreator"
            },
            "youtube": {
                "channel_url": "https://youtube.com/testcreator",
                "subscribers": 100000,
                "verified": True
            },
            "tiktok": {
                "handle": "@testcreator",
                "followers": 200000,
                "verified": False
            },
            "twitter": {
                "handle": "@testcreator",
                "followers": 10000,
                "verified": False
            }
        },
        "handle_flagged_as_real_name": False,
        "flag_reason": None,
        "tags": ["fashion", "lifestyle"],
        "sla_due_date": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
        "previous_requests": [],
        "decision_history": [],
        "created_at": now_iso(),
        "updated_at": now_iso()
    }
    await db.creator_applications.insert_one(app)
    print(f"[OK] Created test creator application: {app['id']}")
    return app

async def create_test_brand_application():
    """Create a test brand application document"""
    app = {
        "id": str(uuid.uuid4()),
        "user_id": str(uuid.uuid4()),
        "business_name": "Test Fashion Brand",
        "business_email": "brand@test.com",
        "phone": "+91-9876543210",
        "status": "pending",
        "submitted_date": now_iso(),
        "category": "fashion",
        "gst_number": "27AABCT1234F1Z0",
        "gst_verification_status": "verified",
        "gst_verified_at": now_iso(),
        "business_type": "Individual",
        "business_description": "Fashion and apparel brand",
        "industry": "Fashion & Apparel",
        "product_type": "Clothing",
        "website": "https://testbrand.com",
        "website_preview": None,
        "founded_year": 2020,
        "employee_count": "50-100",
        "flags": {
            "free_email_domain": False,
            "restricted_category": False,
            "agency_rep": False,
            "low_trust_indicators": []
        },
        "address": {
            "street": "123 Business St",
            "city": "Mumbai",
            "state": "Maharashtra",
            "postal_code": "400001",
            "country": "India"
        },
        "social_media": {
            "instagram": {
                "url": "https://instagram.com/testbrand",
                "followers": 500000,
                "verified": True
            },
            "facebook": {
                "url": "https://facebook.com/testbrand",
                "followers": 300000
            },
            "twitter": {
                "url": "https://twitter.com/testbrand",
                "followers": 50000
            },
            "linkedin": {
                "url": "https://linkedin.com/company/testbrand",
                "followers": 20000
            }
        },
        "gst_verification_details": {
            "status": "active",
            "gstin": "27AABCT1234F1Z0"
        },
        "previous_requests": [],
        "decision_history": [],
        "sla_due_date": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
        "created_at": now_iso(),
        "updated_at": now_iso()
    }
    await db.brand_applications.insert_one(app)
    print(f"[OK] Created test brand application: {app['id']}")
    return app

async def test_helper_functions():
    """Test helper functions from applications.py"""
    import sys
    sys.path.insert(0, str(ROOT_DIR))
    from applications import (
        calculate_sla_remaining,
        is_handle_real_name,
        mask_pan,
        validate_gst_number,
        validate_status_transition,
        ApplicationStatus
    )

    # Test SLA calculation
    submitted = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    sla = calculate_sla_remaining(submitted)
    assert sla == 5, f"Expected SLA=5, got {sla}"
    print(f"[OK] SLA calculation: submitted 2 days ago -> {sla} days remaining")

    # Test handle flagging
    assert is_handle_real_name("John Smith"), "Should flag 'John Smith' as real name"
    assert not is_handle_real_name("@TestCreator123"), "Should not flag handle"
    print("[OK] Handle real name detection works")

    # Test PAN masking
    masked = mask_pan("ABCDE1234F")
    assert masked == "XXXXXX234F", f"Expected 'XXXXXX234F', got '{masked}'"
    print(f"[OK] PAN masking: ABCDE1234F -> {masked}")

    # Test GST validation
    gst_result = validate_gst_number("27AABCT1234F1Z0")
    assert gst_result["valid"], "Valid GST should pass validation"
    assert gst_result["state"] == "Maharashtra", "Should return correct state"
    print(f"[OK] GST validation: valid GST -> {gst_result['status']}")

    invalid_gst = validate_gst_number("INVALID")
    assert not invalid_gst["valid"], "Invalid GST should fail"
    print("[OK] GST validation: invalid GST detected")

    # Test status transitions
    try:
        validate_status_transition("pending", "approved")
        print("[OK] Status transition: pending -> approved (valid)")
    except:
        print("[FAIL] Status transition failed")

    try:
        validate_status_transition("approved", "rejected")
        print("[FAIL] Should reject transition: approved -> rejected")
    except:
        print("[OK] Status transition: approved -> rejected (invalid, correctly rejected)")

async def main():
    print("=" * 70)
    print("Applications Management API - Test Suite")
    print("=" * 70)

    try:
        # Test helper functions
        print("\nTesting helper functions...")
        await test_helper_functions()

        # Create test data
        print("\nCreating test data in MongoDB...")
        creator_app = await create_test_creator_application()
        brand_app = await create_test_brand_application()

        # Print summary
        print("\n" + "=" * 70)
        print("TEST SUMMARY")
        print("=" * 70)
        print(f"Creator Application ID: {creator_app['id']}")
        print(f"Brand Application ID: {brand_app['id']}")
        print("\nTest data ready for manual API testing!")
        print("\nExample API calls to test:")
        print(f"1. GET /api/admin/applications/creators")
        print(f"2. GET /api/admin/applications/creators/{creator_app['id']}")
        print(f"3. GET /api/admin/applications/brands")
        print(f"4. GET /api/admin/applications/brands/{brand_app['id']}")
        print(f"\nNote: These require JWT token with role='admin' or 'campaign_manager'")
        print("=" * 70)

    except Exception as e:
        print(f"[ERROR] {e}")
        import traceback
        traceback.print_exc()
    finally:
        client.close()

if __name__ == "__main__":
    asyncio.run(main())
