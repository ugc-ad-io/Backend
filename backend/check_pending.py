import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

async def check_pending():
    client = AsyncIOMotorClient('mongodb://localhost:27017')
    db = client['test_database']
    
    # Get pending campaigns
    pending = await db.campaigns.find({"status": "pending_approval"}, {"_id": 0}).to_list(100)
    
    print(f"Pending Campaigns: {len(pending)}")
    
    # Get all campaigns with all statuses
    all_campaigns = await db.campaigns.find({}, {"_id": 0}).to_list(100)
    
    statuses = {}
    for c in all_campaigns:
        s = c.get('status', 'unknown')
        statuses[s] = statuses.get(s, 0) + 1
    
    print(f"\nCampaigns by Status:")
    for status, count in statuses.items():
        print(f"  {status}: {count}")
    
    client.close()

asyncio.run(check_pending())
