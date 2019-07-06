import requests


class SecurityTrailsAPI():
    def __init__(self, api_key):
        self.key = api_key
        self.base_api_url = "https://api.securitytrails.com/v1/"
        self.headers = {'apikey': self.key, 'Content-Type': 'application/json'}

    def get_domain(self, domain):
        get_domain_endpoint = self.base_api_url + 'domain/' + domain
        get_domain_response = requests.get(get_domain_endpoint,
                                           headers=self.headers)
        if get_domain_response.raise_for_status():
            raise Exception(self._return_error(
                            get_domain_endpoint.status_code))
        return get_domain_response.json()

    def list_subdomains(self, domain):
        list_subdomains_endpoint = (self.base_api_url +
                                    'domain/{}/subdomains'.format(domain))
        list_subdomains_response = requests.get(list_subdomains_endpoint,
                                                headers=self.headers)
        if list_subdomains_response.raise_for_status():
            raise Exception(self._return_error(
                list_subdomains_response.status_code))
        return list_subdomains_response.json()

    def list_tags(self, domain):
        list_tags_endpoint = (self.base_api_url +
                              'domain/{}/tags'.format(domain))
        list_tags_response = requests.get(list_tags_endpoint,
                                          headers=self.headers)
        if list_tags_response.raise_for_status():
            raise Exception(self._return_error(
                list_tags_response.status_code))
        return list_tags_response.json()

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

    def usage(self):
        usage_endpoint = self.base_api_url + 'account/usage'
        usage_response = requests.get(usage_endpoint, headers=self.headers)
        if usage_response.raise_for_status():
            raise Exception(self._return_error(usage_response.status_code))
        return usage_response.json()
