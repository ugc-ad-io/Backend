import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

async def check_campaigns():
    client = AsyncIOMotorClient('mongodb://localhost:27017')
    db = client['test_database']
    
    # Get all campaigns
    campaigns = await db.campaigns.find({}, {"_id": 0}).to_list(100)
    
    print(f"Total Campaigns: {len(campaigns)}\n")
    
    for campaign in campaigns:
        print(f"Campaign ID: {campaign.get('id')}")
        print(f"Title: {campaign.get('title')}")
        print(f"Status: {campaign.get('status')}")
        print(f"Business ID: {campaign.get('business_id')}")
        print("---")
    
    client.close()

asyncio.run(check_campaigns())
