import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

async def delete_test_campaigns():
    client = AsyncIOMotorClient('mongodb+srv://ugcadio_db_user:O6ZMqyJKXnt6Tfg8@cluster0.peraduo.mongodb.net/')
    db = client['test_database']
    
    # Delete all campaigns with title "Test Campaign - Product Review"
    result = await db.campaigns.delete_many({
        'title': 'Test Campaign - Product Review'
    })
    
    print(f"Deleted: {result.deleted_count} test campaigns")
    
    client.close()

asyncio.run(delete_test_campaigns())
