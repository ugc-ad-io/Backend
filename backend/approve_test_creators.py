import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

async def approve_test_creators():
    client = AsyncIOMotorClient('mongodb://localhost:27017')
    db = client['test_database']

    emails = ['testcreator@test.com', 'testcreator2@test.com']

    for email in emails:
        result = await db.users.update_one(
            {'email': email},
            {'$set': {
                'approval_status': 'approved',
                'profile_completed': True
            }}
        )
        print(f'{email}: Approved! Modified: {result.modified_count}')

    client.close()

asyncio.run(approve_test_creators())
