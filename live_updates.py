"""A shared invalidation cursor; contains no business or user data."""
import logging
import uuid

from starlette.middleware.base import BaseHTTPMiddleware


class LiveUpdatesMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, database):
        super().__init__(app)
        self.database = database

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        path = request.url.path
        if (request.method in {"POST", "PUT", "PATCH", "DELETE"}
                and path.startswith("/api/") and response.status_code < 400
                and not path.startswith(("/api/auth/", "/api/live/"))
                and "typing" not in path and "read" not in path.split("/")):
            try:
                await self.database.live_updates.update_one(
                    {"_id": "revision"}, {"$set": {"version": uuid.uuid4().hex}}, upsert=True
                )
            except Exception:
                logging.getLogger(__name__).exception("Could not publish update cursor")
        return response
