import requests


class SecurityTrailsAPI():
    def __init__(self, api_key):
        self.key = api_key
        self.base_api_url = "https://api.securitytrails.com/v1/"
        self.headers = {'apikey': self.key, 'Content-Type': 'application/json'}

    def ping(self):
        ping_endpoint = self.base_api_url + 'ping'
        ping_response = requests.get(ping_endpoint, headers=self.headers)
        if ping_response.raise_for_status():
            raise Exception("Unable to connect to SecurityTrails API.")
        return ping_response.json()

    @staticmethod
    def _return_error(status_code):
        error_messages = {401: "Invalid SecurityTrails API key",
                          429: "Too many requests. Wait and try again.",
                          500: "An internal error occured."}
        return error_messages[status_code]
