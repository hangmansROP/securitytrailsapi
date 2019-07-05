import os
import unittest
import securitytrails


class SecurityTrailsTests(unittest.TestCase):
    def setUp(self):
        self.apikey = os.environ['API_KEY']
        self.valid_api = securitytrails.SecurityTrailsAPI(self.apikey)
        self.invalid_api = securitytrails.SecurityTrailsAPI("INVALID")

    def test_ping_exception_incorrect_api_key(self):
        with self.assertRaises(Exception):
            self.invalid_api.ping()

    def test_ping_response_content_equals_success(self):
        ping_response = self.valid_api.ping()
        self.assertTrue(ping_response['success'])

    def test_return_error_message_values(self):
        self.assertEqual(self.valid_api._return_error(401),
                         "Invalid SecurityTrails API key")
        self.assertEqual(self.valid_api._return_error(429),
                         "Too many requests. Wait and try again.")
        self.assertEqual(self.valid_api._return_error(500),
                         "An internal error occured.")

    def test_usage_returns_usage_values(self):
        test_usage = self.valid_api.usage()
        self.assertIsInstance(test_usage, dict)
        self.assertIsInstance(test_usage['current_monthly_usage'], int)
        self.assertIsInstance(test_usage['allowed_monthly_usage'], int)
