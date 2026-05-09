import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

async def test():
    client = AsyncIOMotorClient('mongodb+srv://ugcadio_db_user:O6ZMqyJKXnt6Tfg8@cluster0.peraduo.mongodb.net/')
    db = client['test_database']
    
    # Get a business user
    business = await db.users.find_one({"role": "business"}, {"_id": 0})
    if not business:
        print("No business user found")
        client.close()
        return
    
    print(f"Business ID: {business.get('id')}")
    print(f"Business Email: {business.get('email')}")
    
    # Get campaigns for this business
    campaigns = await db.campaigns.find(
        {"business_id": business['id']},
        {"_id": 0, "id": 1, "title": 1}
    ).to_list(100)
    
    print(f"\nCampaigns for this business: {len(campaigns)}")
    for c in campaigns:
        print(f"  - {c['id']}: {c['title']}")
    
    campaign_ids = [c['id'] for c in campaigns]
    
    # Get work submissions
    work = await db.work_submissions.find(
        {"campaign_id": {"$in": campaign_ids}, "status": "submitted"},
        {"_id": 0}
    ).to_list(100)
    
    print(f"\nWork submissions pending: {len(work)}")
    for w in work:
        print(f"  - {w.get('id')}: {w.get('status')}")
    
    client.close()

asyncio.run(test())
