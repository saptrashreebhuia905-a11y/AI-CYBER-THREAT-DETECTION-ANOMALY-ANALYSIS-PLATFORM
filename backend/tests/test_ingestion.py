import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

from bson import ObjectId

from app.main import _store_log
from app.schemas import SecurityLogSchema


class FakeLogCollection:
    def __init__(self):
        self.document = None

    async def insert_one(self, document):
        self.document = document
        return SimpleNamespace(inserted_id=ObjectId())


class IngestionTests(unittest.IsolatedAsyncioTestCase):
    async def test_detected_event_is_saved_with_open_alert_metadata(self):
        collection = FakeLogCollection()
        event = SecurityLogSchema(
            timestamp=datetime.now(timezone.utc),
            source_ip="198.51.100.44",
            user_id="test-user",
            endpoint="/api/login",
            request_rate=180,
            login_status="FAILED",
            failed_attempts=8,
        )

        with patch("app.main.get_logs_collection", return_value=collection):
            result = await _store_log(event)

        self.assertTrue(result["is_alert"])
        self.assertTrue(collection.document["is_alert"])
        self.assertEqual(collection.document["alert_status"], "open")
        self.assertEqual(collection.document["source_ip"], "198.51.100.44")


if __name__ == "__main__":
    unittest.main()
