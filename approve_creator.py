import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

async def approve_creator():
    client = AsyncIOMotorClient('mongodb://localhost:27017')
    db = client['test_database']
    
    result = await db.users.update_one(
        {'email': 'creator@test.com'},
        {'$set': {
            'approval_status': 'approved',
            'profile_completed': True
        }}
    )
    
    print(f'Creator approved! Modified: {result.modified_count}')
    client.close()

asyncio.run(approve_creator())
