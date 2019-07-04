import requests


class SecurityTrailsAPI():
	def __init__(self, api_key):
		self.key = api_key
		self.base_api_url = "https://api.securitytrails.com/v1/"

	def ping(self):
		return 200
