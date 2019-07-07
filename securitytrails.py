import json
import requests


class SecurityTrailsAPI():
    def __init__(self, api_key):
        self.key = api_key
        self.base_api_url = "https://api.securitytrails.com/v1/"
        self.headers = {'apikey': self.key, 'Content-Type': 'application/json'}

    def explore_ips(self, ipaddress):
        explore_ips_endpoint = (self.base_api_url +
                                'ips/nearby/{}'.format(ipaddress))
        explore_ips_response = requests.get(explore_ips_endpoint,
                                            headers=self.headers)
        if explore_ips_response.raise_for_status():
            raise Exception(self._return_error(
                explore_ips_response.status_code))
        return explore_ips_response.json()

    def feeds_domains(self, record_type, search_filter, tld, ns, date):
        find_domains_endpoint = (self.base_api_url +
                                 'feeds/domains/%s?' +
                                 'filter=%s&tld=%s&ns=%s&date=%s',
                                 record_type, search_filter,
                                 tld, ns, date)
        find_domains_response = requests.get(find_domains_endpoint,
                                             headers=self.headers)
        if find_domains_response.raise_for_status():
            raise Exception(self._return_error(
                find_domains_response.status_code))
        return find_domains_response.json()

    def find_associated_domains(self, domain):
        find_domains_endpoint = (self.base_api_url +
                                 'domain/{}/associated'.format(domain))
        find_domains_response = requests.get(find_domains_endpoint,
                                             headers=self.headers)
        if find_domains_response.raise_for_status():
            raise Exception(self._return_error(
                            find_domains_response.status_code))
        return find_domains_response.json()

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
        get_whois_response = requests.get(get_whois_endpoint,
                                          headers=self.headers)
        if get_whois_response.raise_for_status():
            raise Exception(self._return_error(
                get_whois_response.status_code))
        return get_whois_response.json()

    def history_by_domain(self, domain, page):
        history_by_domain_endpoint = (self.base_api_url +
                                      'history/{}/whois?page={}'.format(
                                          domain, page))
        history_by_domain_response = requests.get(history_by_domain_endpoint,
                                                  headers=self.headers)
        if history_by_domain_response.raise_for_status():
            raise Exception(self._return_error(
                history_by_domain_response.status_code))
        return history_by_domain_response.json()

    def history_by_record(self, domain, record_type):
        history_by_record_endpoint = (self.base_api_url +
                                      'history/{}/dns/{}'.format(
                                          domain, record_type))
        history_by_record_response = requests.get(history_by_record_endpoint,
                                                  headers=self.headers)
        if history_by_record_response.raise_for_status():
            raise Exception(self._return_error(
                history_by_record_response.status_code))
        return history_by_record_response.json()

    def ip_search_stats(self, query):
        ip_search_stats_endpoint = (self.base_api_url + 'domains/stats')
        ip_param = '{"query": ' + query + '}'
        ip_search_stats_response = requests.post(
            ip_search_stats_endpoint,
            headers=self.headers,
            data=ip_param)
        if ip_search_stats_response.raise_for_status():
            raise Exception(self._return_error(
                ip_search_stats_response.status_code))
        return ip_search_stats_response.json()

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
        search_domain_filter_response = requests.post(
            search_domain_filter_endpoint,
            headers=self.headers,
            data=filter_param)
        if search_domain_filter_response.raise_for_status():
            raise Exception(self._return_error(
                search_domain_filter_response.status_code))
        return search_domain_filter_response.json()

    def search_domain_dsl(self, query, include_ips, page, scroll):
        search_domain_dsl_endpoint = (self.base_api_url + 'domains/list?'
                                      + 'include_ips=%s&page=%s'
                                      + '&scroll=%s', include_ips,
                                      page, scroll)
        query_param = '{"query": %s}', query
        search_domain_dsl_response = requests.post(
            search_domain_dsl_endpoint,
            headers=self.headers,
            data=query_param)
        if search_domain_dsl_response.raise_for_status():
            raise Exception(self._return_error(
                search_domain_dsl_response.status_code))
        return search_domain_dsl_response.json()

    def search_ips(self, query, page):
        search_ips = (self.base_api_url +
                      'ips/list?&page={}'.format(page))
        ip_params = '{"query": %s}', query
        search_ips_response = requests.post(search_ips,
                                            headers=self.headers,
                                            data=ip_params)
        if search_ips_response.raise_for_status():
            raise Exception(self._return_error(
                search_ips_response.status_code))
        return search_ips_response.json()

    def search_statistics(self, search_filter):
        search_statistics_endpoint = (self.base_api_url + 'domains/stats')
        filter_param = '{"filter": ' + json.dumps(search_filter.__dict__) + '}'
        search_statistics_response = requests.post(
            search_statistics_endpoint,
            headers=self.headers,
            data=filter_param)
        if search_statistics_response.raise_for_status():
            raise Exception(self._return_error(
                search_statistics_response.status_code))
        return search_statistics_response.json()

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
