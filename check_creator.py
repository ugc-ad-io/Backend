import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

async def check_creator():
    client = AsyncIOMotorClient('mongodb://localhost:27017')
    db = client['test_database']
    
    user = await db.users.find_one({'email': 'creator@test.com'}, {'_id': 0, 'password': 0})
    
    if user:
        print("Creator found:")
        for key, value in user.items():
            print(f"  {key}: {value}")
    else:
        print("Creator with email 'creator@test.com' not found.")
    
    client.close()

if __name__ == "__main__":
    asyncio.run(check_creator())