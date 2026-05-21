import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
import uuid
from datetime import datetime, timezone

async def create_test_campaign():
    client = AsyncIOMotorClient('mongodb://localhost:27017')
    db = client['test_database']
    
    # Get a business user or create one
    business = await db.users.find_one({'role': 'business'})
    
    if not business:
        # Create a business account first
        business_id = str(uuid.uuid4())
        await db.users.insert_one({
            'id': business_id,
            'email': 'testbusiness@test.com',
            'password': 'hashed_password',
            'role': 'business',
            'nickname': '@TestBusiness',
            'approval_status': 'approved',
            'profile_completed': True,
            'created_at': datetime.now(timezone.utc).isoformat()
        })
    else:
        business_id = business['id']
    
    # Create a test campaign
    campaign_id = str(uuid.uuid4())
    campaign = {
        'id': campaign_id,
        'business_id': business_id,
        'title': 'Test Campaign - Product Review',
        'description': 'We need creators to review our new product',
        'budget': 50000,
        'status': 'active',  # Set to ACTIVE so creators can see it
        'bids': [],
        'selected_creator': None,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'updated_at': datetime.now(timezone.utc).isoformat()
    }
    
    result = await db.campaigns.insert_one(campaign)
    print("Test Campaign Created!")
    print(f"Campaign ID: {campaign_id}")
    print(f"Title: Test Campaign - Product Review")
    print(f"Budget: Rs 50,000")
    print(f"Status: ACTIVE")
    
    client.close()

asyncio.run(create_test_campaign())
