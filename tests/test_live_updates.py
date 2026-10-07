from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock

from live_updates import LiveUpdatesMiddleware


class LiveUpdatesTests(IsolatedAsyncioTestCase):
    async def check_request(self, method, path, status):
        database = SimpleNamespace(live_updates=SimpleNamespace(update_one=AsyncMock()))
        middleware = LiveUpdatesMiddleware(app=AsyncMock(), database=database)
        response = SimpleNamespace(status_code=status)
        result = await middleware.dispatch(
            SimpleNamespace(method=method, url=SimpleNamespace(path=path)),
            AsyncMock(return_value=response),
        )
        self.assertIs(result, response)
        return database.live_updates.update_one

    async def test_successful_mutation_publishes_shared_cursor(self):
        write = await self.check_request("POST", "/api/payments/verify", 200)
        write.assert_awaited_once()
        args = write.call_args
        self.assertEqual(args.args[0], {"_id": "revision"})
        self.assertTrue(args.args[1]["$set"]["version"])

    async def test_reads_failed_mutations_and_typing_do_not_publish(self):
        for method, path, status in [
            ("GET", "/api/campaigns", 200),
            ("POST", "/api/campaigns", 403),
            ("POST", "/api/auth/login", 200),
            ("POST", "/api/chat/typing", 200),
        ]:
            write = await self.check_request(method, path, status)
            write.assert_not_awaited()
