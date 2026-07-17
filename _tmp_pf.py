import asyncio, os, json
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
load_dotenv()

VIDEO_EXT = __import__("re").compile(r"\.(mp4|mov|webm|m4v|avi|mkv)(\?|#|$)", __import__("re").I)


def collect(v):
    out = []
    def push(x):
        if isinstance(x, str) and x.strip(): out.append(x.strip())
    def from_obj(o):
        if isinstance(o.get("urls"), list):
            for u in o["urls"]: push(u)
        push(o.get("url") or o.get("file_url") or o.get("src") or o.get("video") or o.get("video_url")
             or o.get("videoUrl") or o.get("original_url") or o.get("image") or o.get("image_url") or o.get("link"))
    if isinstance(v, str): push(v)
    elif isinstance(v, list):
        for it in v:
            if isinstance(it, str): push(it)
            elif isinstance(it, dict): from_obj(it)
    elif isinstance(v, dict): from_obj(v)
    return out


async def main():
    cli = AsyncIOMotorClient(os.environ.get("MONGO_URL") or os.environ["MONGODB_URI"])
    db = cli[os.environ.get("DB_NAME", "test_database")]
    u = await db.users.find_one({"email": "arushikhare27@gmail.com"}, {"_id": 0})
    if not u:
        print("SKIP: Aru not found"); return
    print("creator:", u.get("nickname"), "role:", u.get("role"))
    pf = u.get("portfolio") or (u.get("profile") or {}).get("portfolio") or []
    print("\nraw portfolio (first item shape):")
    print(" ", json.dumps(pf[0], default=str)[:300] if pf else "(empty)")

    urls = collect(pf)
    print(f"\nOLD extractor (url/file_url/src/video/video_url only): would miss videoUrl/urls")
    print(f"NEW extractor found {len(urls)} url(s):")
    vids = [x for x in urls if VIDEO_EXT.search(x)]
    for x in urls:
        print(f"  {'[VIDEO]' if VIDEO_EXT.search(x) else '[other]'} {x}")
    print(f"\n=> admin will see {len(vids)} playable video(s)  [want >=1]")
    cli.close()


asyncio.run(main())
