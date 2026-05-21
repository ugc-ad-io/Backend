import asyncio
import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'backend'))

from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import bcrypt
import uuid
from datetime import datetime, timezone

# Load environment
ROOT_DIR = Path(__file__).parent.parent / 'backend'
load_dotenv(ROOT_DIR / '.env')

async def create_admin_user():
    # Connect to MongoDB
    mongo_url = os.environ['MONGO_URL']
    client = AsyncIOMotorClient(mongo_url)
    db = client[os.environ['DB_NAME']]
    
    # Admin credentials
    admin_email = "admin@ugcplatform.com"
    admin_password = "Admin@2025"
    
    # Check if admin already exists
    existing_admin = await db.users.find_one({"email": admin_email})
    if existing_admin:
        print(f"✓ Admin user already exists: {admin_email}")
        print(f"  Email: {admin_email}")
        print(f"  Password: {admin_password}")
        client.close()
        return
    
    # Hash password
    hashed_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # Create admin user
    admin_doc = {
        "id": str(uuid.uuid4()),
        "email": admin_email,
        "password": hashed_password,
        "role": "admin",
        "nickname": "@AdminMaster",
        "profile_completed": True,
        "approval_status": "approved",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "balance": 0.0
    }
    
    await db.users.insert_one(admin_doc)
    print("✓ Admin user created successfully!")
    print(f"  Email: {admin_email}")
    print(f"  Password: {admin_password}")
    print(f"  Role: admin")
    print(f"\nYou can now login with these credentials.")
    
    client.close()

if __name__ == "__main__":
    asyncio.run(create_admin_user())
