import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

async def check():
    client = AsyncIOMotorClient('mongodb+srv://ugcadio_db_user:O6ZMqyJKXnt6Tfg8@cluster0.peraduo.mongodb.net/')
    db = client['test_database']
    
    # Check work_submissions
    work_subs = await db.work_submissions.find({}, {"_id": 0}).to_list(100)
    print(f"Work Submissions: {len(work_subs)}")
    for work in work_subs:
        print(f"  - {work.get('id')}: status={work.get('status')}, campaign={work.get('campaign_id')}")
    
    print("\n" + "="*50)
    
    # Check campaign statuses
    campaigns = await db.campaigns.find({}, {"_id": 0, "id": 1, "status": 1, "title": 1}).to_list(100)
    print(f"Campaigns: {len(campaigns)}")
    for c in campaigns:
        print(f"  - {c.get('title')}: {c.get('status')}")
    
    client.close()

asyncio.run(check())
