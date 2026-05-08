import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
import bcrypt
import uuid
from datetime import datetime, timezone
import os
from dotenv import load_dotenv

load_dotenv()

async def create_test_brand():
    # Test credentials
    email = 'testbrand@test.com'
    password = 'TestPassword123'
    brand_name = 'Test Brand'

    # MongoDB connection
    mongo_url = os.getenv('MONGO_URL', 'mongodb://localhost:27017')
    db_name = os.getenv('DB_NAME', 'test_database')

    client = AsyncIOMotorClient(mongo_url)
    db = client[db_name]

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    brand_data = {
        'id': str(uuid.uuid4()),
        'email': email,
        'password': hashed_password,
        'nickname': brand_name,
        'full_name': brand_name,
        'approval_status': 'approved',
        'profile_completed': True,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'updated_at': datetime.now(timezone.utc).isoformat(),
        'role': 'business',
        'balance': 0.0,
        'banned': False
    }

    # Insert into database
    result = await db.users.insert_one(brand_data)

    print("=" * 50)
    print("[SUCCESS] NEW BRAND ACCOUNT CREATED")
    print("=" * 50)
    print(f"Email:    {email}")
    print(f"Password: {password}")
    print(f"Role:     business")
    print("=" * 50)
    print("Account ID:", result.inserted_id)
    print("=" * 50)

    client.close()

if __name__ == "__main__":
    asyncio.run(create_test_brand())
