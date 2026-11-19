import unittest

from app.detection.aggregator import evaluate_event
from app.detection.rules import evaluate_rules


class DetectionTests(unittest.TestCase):
    def test_normal_event_does_not_create_alert(self):
        event = {"request_rate": 10, "failed_attempts": 0, "login_status": "SUCCESS"}

        result = evaluate_event(event)

        self.assertFalse(result["is_alert"])
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["severity"], "low")

    def test_brute_force_rule_flags_repeated_failures(self):
        event = {"request_rate": 20, "failed_attempts": 8, "login_status": "FAILED"}

        score, reasons = evaluate_rules(event)

        self.assertEqual(score, 50)
        self.assertIn("Repeated failed login attempts", reasons)

    def test_high_request_rate_creates_alert(self):
        event = {"request_rate": 180, "failed_attempts": 0, "login_status": "SUCCESS"}

        result = evaluate_event(event)

        self.assertTrue(result["is_alert"])
        self.assertGreaterEqual(result["risk_score"], 40)
        self.assertIn("High request rate", result["reasons"])


if __name__ == "__main__":
    unittest.main()
