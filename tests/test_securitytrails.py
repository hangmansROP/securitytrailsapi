import os
import unittest
import securitytrails
from time import sleep


class SecurityTrailsTests(unittest.TestCase):
    def setUp(self):
        self.apikey = os.environ['API_KEY']
        self.valid_api = securitytrails.SecurityTrailsAPI(self.apikey)
        self.invalid_api = securitytrails.SecurityTrailsAPI("INVALID")

    @staticmethod
    def _rate_limit():
        sleep(1)

    def test_ping_exception_incorrect_api_key(self):
        with self.assertRaises(Exception):
            self.invalid_api.ping()

    def test_ping_response_content_equals_success(self):
        self._rate_limit()
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
        self._rate_limit()
        test_usage = self.valid_api.usage()
        self.assertIsInstance(test_usage, dict)
        self.assertIsInstance(test_usage['current_monthly_usage'], int)
        self.assertIsInstance(test_usage['allowed_monthly_usage'], int)

    def test_get_domain_endpoint_invalid_hostname(self):
        self._rate_limit()
        with self.assertRaises(Exception):
            self.valid_api.get_domain("Invalid!^%$&")

    def test_list_subdomains_endpoint(self):
        self._rate_limit()
        self.assertIsInstance(self.valid_api.list_subdomains(
            "google.com"), dict)

    def test_list_tags_returns_json_dict(self):
        self._rate_limit()
        self.assertIsInstance(self.valid_api.list_tags("google.com"), dict)

    def test_find_associated_domains_returns_exception_no_sub(self):
        self._rate_limit()
        with self.assertRaises(Exception):
            self.valid_api.find_associated_domains("google.com")

    def test_get_whois_raises_exception(self):
        self._rate_limit()
        with self.assertRaises(Exception):
            self.valid_api.get_whois("google.com")
