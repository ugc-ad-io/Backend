import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
import bcrypt
import uuid
from datetime import datetime, timezone

async def setup_creator():
    client = AsyncIOMotorClient('mongodb://localhost:27017')
    db = client['test_database']

    # Delete old incorrect creator accounts
    await db.users.delete_many({'email': 'testcreator@test.com'})
    print("[INFO] Deleted old creator accounts")

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
    print("[SUCCESS] CREATOR ACCOUNT READY")
    print("=" * 50)
    print(f"Email:    {email}")
    print(f"Password: {password}")
    print("=" * 50)

    client.close()

if __name__ == "__main__":
    asyncio.run(setup_creator())
