import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
import bcrypt
import uuid
from datetime import datetime, timezone

async def create_test_creator():
    client = AsyncIOMotorClient('mongodb://localhost:27017')
    db = client['test_database']

    # Test credentials
    email = 'testcreator@test.com'
    password = 'TestPassword123'

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    creator_data = {
        'id': str(uuid.uuid4()),
        'email': email,
        'password': hashed_password,
        'nickname': 'Test Creator',
        'full_name': 'Test Creator',
        'approval_status': 'approved',
        'profile_completed': True,
        'created_at': datetime.now(timezone.utc),
        'updated_at': datetime.now(timezone.utc),
        'role': 'creator'
    }

    # Insert into database
    result = await db.users.insert_one(creator_data)

    print("=" * 50)
    print("[SUCCESS] NEW CREATOR ACCOUNT CREATED")
    print("=" * 50)
    print(f"Email:    {email}")
    print(f"Password: {password}")
    print("=" * 50)
    print("Account ID:", result.inserted_id)
    print("=" * 50)

    client.close()

if __name__ == "__main__":
    asyncio.run(create_test_creator())
