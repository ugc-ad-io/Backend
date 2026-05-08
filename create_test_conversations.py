import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
import bcrypt
import uuid
from datetime import datetime, timezone, timedelta

async def create_test_data():
    client = AsyncIOMotorClient('mongodb://localhost:27017')
    db = client['test_database']

    # Test Creator (already exists)
    creator_email = 'testcreator@test.com'
    creator = await db.users.find_one({'email': creator_email})

    if not creator:
        print("[FAIL] Creator account not found. Run setup_creator.py first.")
        client.close()
        return

    creator_id = creator['id']

    # Create Test Business Account
    business_id = str(uuid.uuid4())
    business_email = 'testbusiness@test.com'
    business_password = 'BizPassword123'
    hashed_password = bcrypt.hashpw(business_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Delete old business account if exists
    await db.users.delete_one({'email': business_email})

    business_data = {
        'id': business_id,
        'email': business_email,
        'password': hashed_password,
        'nickname': 'Glow & Co',
        'full_name': 'Glow & Co',
        'approval_status': 'approved',
        'profile_completed': True,
        'created_at': datetime.now(timezone.utc),
        'updated_at': datetime.now(timezone.utc),
        'role': 'business'
    }

    await db.users.insert_one(business_data)
    print("[OK] Business account created: " + business_email)

    # Delete old messages/conversations
    await db.messages.delete_many({
        '$or': [
            {'sender_id': creator_id, 'recipient_id': business_id},
            {'sender_id': business_id, 'recipient_id': creator_id}
        ]
    })

    # Create sample conversations
    now = datetime.now(timezone.utc)
    messages = [
        {
            'id': str(uuid.uuid4()),
            'sender_id': business_id,
            'recipient_id': creator_id,
            'message': 'Hi! We love your portfolio. Are you interested in our summer campaign?',
            'timestamp': now - timedelta(hours=2),
            'read': False
        },
        {
            'id': str(uuid.uuid4()),
            'sender_id': creator_id,
            'recipient_id': business_id,
            'message': 'Thanks! Yes, I am definitely interested. Can you share more details about the brief?',
            'timestamp': now - timedelta(hours=1, minutes=45),
            'read': True
        },
        {
            'id': str(uuid.uuid4()),
            'sender_id': business_id,
            'recipient_id': creator_id,
            'message': 'Perfect! Just submitted the final deliverables. Planning to shoot the main hooks tomorrow morning.',
            'timestamp': now - timedelta(minutes=30),
            'read': False
        },
        {
            'id': str(uuid.uuid4()),
            'sender_id': creator_id,
            'recipient_id': business_id,
            'message': 'Perfect! Please remember to emphasize the summer discount code in the first 3 seconds.',
            'timestamp': now - timedelta(minutes=15),
            'read': True
        }
    ]

    await db.messages.insert_many(messages)
    print("[OK] Sample messages created: " + str(len(messages)) + " messages")

    # Delete old campaigns
    await db.campaigns.delete_many({
        'selected_creator': creator_id,
        'business_id': business_id
    })

    # Create a sample campaign/deal
    campaign_id = str(uuid.uuid4())
    campaign = {
        'id': campaign_id,
        'title': 'Summer Hydration Marketing Campaign',
        'business_id': business_id,
        'selected_creator': creator_id,
        'brief_text': 'We need a 60-second video showcasing our new summer hydration drink line. Focus on refreshment and outdoor activities.',
        'status': 'in_progress',
        'budget_min': 15000,
        'budget_max': 18750,
        'estimated_delivery_days': 7,
        'work_started_at': now - timedelta(days=2),
        'brief_attachments': [
            'https://example.com/Campaign_Brief.pdf',
            'https://example.com/Script_v2_Final.docx',
            'https://example.com/Reference_Mood_Board.zip'
        ],
        'created_at': now - timedelta(days=5),
        'updated_at': now
    }

    await db.campaigns.insert_one(campaign)
    print("[OK] Sample campaign created: " + campaign['title'])

    print("\n" + "="*50)
    print("[SUCCESS] TEST DATA READY")
    print("="*50)
    print("\n[CREATOR]")
    print("   Email:    " + creator_email)
    print("   Password: TestPassword123")
    print("   ID:       " + creator_id)
    print("\n[BUSINESS]")
    print("   Email:    " + business_email)
    print("   Password: " + business_password)
    print("   ID:       " + business_id)
    print("\n[DATA]")
    print("   Conversations: 4 messages between accounts")
    print("   Campaign: Summer Hydration Marketing Campaign (Rs.18,750)")
    print("="*50)

    client.close()

if __name__ == "__main__":
    asyncio.run(create_test_data())
