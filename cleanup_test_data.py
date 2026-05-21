import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

async def cleanup_test_data():
    client = AsyncIOMotorClient('mongodb://localhost:27017')
    db = client['test_database']

    # Delete all messages
    result_msgs = await db.messages.delete_many({})
    print(f"[OK] Deleted {result_msgs.deleted_count} messages")

    # Delete all campaigns
    result_camps = await db.campaigns.delete_many({})
    print(f"[OK] Deleted {result_camps.deleted_count} campaigns")

    print("\n" + "="*50)
    print("[SUCCESS] TEST DATA CLEANED")
    print("="*50)
    print("Messages page ab clean hoga - no conversations")
    print("="*50)

    client.close()

if __name__ == "__main__":
    asyncio.run(cleanup_test_data())
