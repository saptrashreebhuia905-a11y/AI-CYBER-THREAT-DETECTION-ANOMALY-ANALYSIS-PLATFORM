import unittest

from app.auth import hash_password, verify_password


class AuthenticationTests(unittest.TestCase):
    def test_password_hash_verifies_only_matching_password(self):
        stored_hash = hash_password("a-long-test-password")

        self.assertTrue(verify_password("a-long-test-password", stored_hash))
        self.assertFalse(verify_password("a-different-password", stored_hash))

    def test_malformed_password_hash_is_rejected(self):
        self.assertFalse(verify_password("password", "not-a-valid-hash"))


if __name__ == "__main__":
    unittest.main()
