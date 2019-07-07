import json
import requests


class SecurityTrailsAPI():
    def __init__(self, api_key):
        self.key = api_key
        self.base_api_url = "https://api.securitytrails.com/v1/"
        self.headers = {'apikey': self.key, 'Content-Type': 'application/json'}

    def find_associated_domains(self, domain):
        find_domains_endpoint = (self.base_api_url +
                                 'domain/{}/associated'.format(domain))
        find_domains_endpoint = requests.get(find_domains_endpoint,
                                             headers=self.headers)
        if find_domains_endpoint.raise_for_status():
            raise Exception(self._return_error(
                            find_domains_endpoint.status_code))
        return find_domains_endpoint.json()

    def get_domain(self, domain):
        get_domain_endpoint = self.base_api_url + 'domain/' + domain
        get_domain_response = requests.get(get_domain_endpoint,
                                           headers=self.headers)
        if get_domain_response.raise_for_status():
            raise Exception(self._return_error(
                            get_domain_endpoint.status_code))
        return get_domain_response.json()

    def get_whois(self, domain):
        get_whois_endpoint = (self.base_api_url +
                              'domain/{}/whois'.format(domain))
        get_whois_endpoint = requests.get(get_whois_endpoint,
                                          headers=self.headers)
        if get_whois_endpoint.raise_for_status():
            raise Exception(self._return_error(
                get_whois_endpoint.status_code))
        return get_whois_endpoint.json()

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

    def search_domain_filter(self, search_filter, include_ips, page):
        search_domain_filter_endpoint = (self.base_api_url + 'domains/list?'
                                         + 'include_ips={}&page={}'.format(
                                             include_ips, page))
        filter_param = '{"filter": ' + json.dumps(search_filter.__dict__) + '}'
        search_domain_filter_endpoint = requests.post(
            search_domain_filter_endpoint,
            headers=self.headers,
            data=filter_param)
        if search_domain_filter_endpoint.raise_for_status():
            raise Exception(self._return_error(
                search_domain_filter_endpoint.status_code))
        return search_domain_filter_endpoint.json()

    def search_statistics(self, search_filter):
        search_statistics_endpoint = (self.base_api_url + 'domains/stats')
        filter_param = '{"filter": ' + json.dumps(search_filter.__dict__) + '}'
        search_statistics_endpoint = requests.post(
            search_statistics_endpoint,
            headers=self.headers,
            data=filter_param)
        if search_statistics_endpoint.raise_for_status():
            raise Exception(self._return_error(
                search_statistics_endpoint.status_code))
        return search_statistics_endpoint.json()

    def usage(self):
        usage_endpoint = self.base_api_url + 'account/usage'
        usage_response = requests.get(usage_endpoint, headers=self.headers)
        if usage_response.raise_for_status():
            raise Exception(self._return_error(usage_response.status_code))
        return usage_response.json()


class SecurityTrailsAPIFilter():
    def __init__(self):
        self.ipv4 = ''
        self.ipv6 = ''
        self.apex_domain = ''
        self.keyword = ''
        self.mx = ''
        self.ns = ''
        self.cname = ''
        self.subdomain = ''
        self.soa_email = ''
        self.tld = ''
        self.whois_email = ''
        self.whois_street1 = ''
        self.whois_street2 = ''
        self.whois_street3 = ''
        self.whois_street4 = ''
        self.whois_telephone = ''
        self.whois_postalCode = ''
        self.whois_organization = ''
        self.whois_name = ''
        self.whois_fax = ''
        self.whois_city = ''
        self.query = ''
