import os, asyncio, motor.motor_asyncio
from dotenv import load_dotenv; load_dotenv()
async def main():
    c = motor.motor_asyncio.AsyncIOMotorClient(os.environ['MONGODB_URI'])
    db = c[os.environ.get('DB_NAME','test_database')]
    async for u in db.users.find({'role':'creator'}, {'email':1,'languages':1,'profile.languages':1}):
        prof = u.get('profile') or {}
        print(f"{u.get('email'):32} top.languages={u.get('languages')!r}  profile.languages={prof.get('languages')!r}")
    c.close()
asyncio.run(main())
