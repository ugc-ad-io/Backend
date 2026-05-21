"""
Database setup script for Gigs collection.
Creates indexes and initializes the collection.
Run this script once to set up the gigs database.
"""

import asyncio
import os
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

async def setup_gigs_db():
    """Initialize gigs collection with indexes"""

    mongo_url = os.environ['MONGO_URL']
    db_name = os.environ['DB_NAME']

    # Connect to MongoDB
    client = AsyncIOMotorClient(mongo_url)
    db = client[db_name]

    print("🔧 Setting up Gigs Database...")

    # Drop existing indexes (except _id) if needed
    # await db.gigs.drop_indexes()

    # Create indexes for optimal performance
    print("📋 Creating indexes...")

    # Index on creator_id for fast creator lookups
    await db.gigs.create_index("creator_id")
    print("  ✓ Created index on creator_id")

    # Index on status for filtering by status
    await db.gigs.create_index("status")
    print("  ✓ Created index on status")

    # Index on created_at for sorting by date
    await db.gigs.create_index([("created_at", -1)])
    print("  ✓ Created index on created_at (descending)")

    # Compound index for common queries
    await db.gigs.create_index([("status", 1), ("created_at", -1)])
    print("  ✓ Created compound index on (status, created_at)")

    # Index on deadline for deadline-based operations
    await db.gigs.create_index("deadline")
    print("  ✓ Created index on deadline")

    # Index on category for filtering
    await db.gigs.create_index("category")
    print("  ✓ Created index on category")

    # Index on gig id for fast lookups
    await db.gigs.create_index("id", unique=True)
    print("  ✓ Created unique index on id")

    # Verify indexes
    print("\n📊 Collection Info:")
    stats = await db.command("collStats", "gigs")
    print(f"  Documents: {stats.get('count', 0)}")
    print(f"  Size: {stats.get('size', 0)} bytes")

    # List all indexes
    indexes = await db.gigs.list_indexes().to_list(None)
    print(f"  Indexes created: {len(indexes)}")

    print("\n✅ Gigs database setup completed successfully!")

    # Close connection
    client.close()

if __name__ == "__main__":
    asyncio.run(setup_gigs_db())
