import os
import unittest
from securitytrailsapi import api_handler
from time import sleep


class SecurityTrailsTests(unittest.TestCase):
    def setUp(self):
        self.apikey = os.environ['API_KEY']
        self.invalid_api = api_handler.SecurityTrailsAPI("INVALID")
        self.search_filter = api_handler.SecurityTrailsAPIFilter()
        self.valid_api = api_handler.SecurityTrailsAPI(self.apikey)

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

    def test_history_by_record_returns_json_dict(self):
        self._rate_limit()
        self.assertIsInstance(self.valid_api.history_by_record(
            "google.com", "a"), dict)

    def test_history_by_domain_raises_exception(self):
        self._rate_limit()
        with self.assertRaises(Exception):
            self.valid_api.history_by_domain("google.com", 1)

    def test_search_domain_filter__raises_exception(self):
        self._rate_limit()
        with self.assertRaises(Exception):
            self.valid_api.search_domain_filter(self.search_filter, True, 1)

    def test_search_domain_dsl_raises_exception(self):
        self._rate_limit()
        with self.assertRaises(Exception):
            self.valid_api.search_domain_dsl("query", True, 1, False)

    def test_search_statistics_raises_exception(self):
        self._rate_limit()
        with self.assertRaises(Exception):
            self.valid_api.search_statistics(self.search_filter)

    def test_explore_ips_returns_dict(self):
        self._rate_limit()
        self.assertIsInstance(self.valid_api.explore_ips(
            "8.8.8.8"), dict)

    def test_search_ips_raises_exception(self):
        self._rate_limit()
        with self.assertRaises(Exception):
            self.valid_api.search_ips("8.8.8.8", 1)

    def test_ip_search_stats_returns_dict(self):
        self._rate_limit()
        self.assertIsInstance(self.valid_api.ip_search_stats(
            "8.8.8.8"), dict)

    def test_feeds_domains_raises_exception(self):
        self._rate_limit()
        self.assertIsInstance(self.valid_api.feeds_domains(
            "all", "ctld", "com", True, "2000-01-01"), dict)

    def test_api_filter_instatiation(self):
        self.assertIs(self.search_filter.ipv4, '')
        self.assertIs(self.search_filter.ipv6, '')
        self.assertIs(self.search_filter.apex_domain, '')
        self.assertIs(self.search_filter.keyword, '')
        self.assertIs(self.search_filter.mx, '')
        self.assertIs(self.search_filter.ns, '')
        self.assertIs(self.search_filter.cname, '')
        self.assertIs(self.search_filter.subdomain, '')
        self.assertIs(self.search_filter.soa_email, '')
        self.assertIs(self.search_filter.tld, '')
        self.assertIs(self.search_filter.whois_email, '')
        self.assertIs(self.search_filter.whois_street1, '')
        self.assertIs(self.search_filter.whois_street2, '')
        self.assertIs(self.search_filter.whois_street3, '')
        self.assertIs(self.search_filter.whois_street4, '')
        self.assertIs(self.search_filter.whois_telephone, '')
        self.assertIs(self.search_filter.whois_postalCode, '')
        self.assertIs(self.search_filter.whois_organization, '')
        self.assertIs(self.search_filter.whois_name, '')
        self.assertIs(self.search_filter.whois_fax, '')
        self.assertIs(self.search_filter.whois_city, '')
        self.assertIs(self.search_filter.query, '')
