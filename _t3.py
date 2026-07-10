import os, jwt, asyncio, motor.motor_asyncio, urllib.request, json
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv; load_dotenv()
sec=os.environ.get('JWT_SECRET','your-secret-key-change-in-production')
async def go():
    c=motor.motor_asyncio.AsyncIOMotorClient(os.environ['MONGODB_URI']); db=c[os.environ.get('DB_NAME','test_database')]
    u=await db.users.find_one({'email':'admin@ugcplatform.com'},{'id':1,'email':1,'role':1}); c.close()
    tok=jwt.encode({'user_id':u['id'],'email':u['email'],'role':u['role'],'exp':datetime.now(timezone.utc)+timedelta(hours=1)},sec,algorithm='HS256')
    tok=tok if isinstance(tok,str) else tok.decode()
    for i in range(3):
        try:
            r=urllib.request.Request('http://localhost:8000/api/admin/shipping/requests', headers={'Authorization':'Bearer '+tok})
            data=json.load(urllib.request.urlopen(r))
            titles=[x.get('campaign_title') for x in data]
            print(f"try{i}: 200  rows={len(data)}  {titles}")
        except urllib.error.HTTPError as e:
            print(f"try{i}: {e.code}  {e.read().decode()[:200]}")
asyncio.run(go())
