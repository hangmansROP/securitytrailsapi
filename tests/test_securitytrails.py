import os
import unittest
import securitytrails

class SecurityTrailsTests(unittest.TestCase):
	def setUp(self):
		self.apikey = os.environ('API_KEY')
		self.api = securitytrails.SecurityTrailsAPI(self.apikey)
	def test_ping_with_correct_api_key(self):
		self.assertEqual(self.api.ping(), 200)