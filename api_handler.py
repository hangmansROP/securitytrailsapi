import json
import requests


class SecurityTrailsAPI:
    def __init__(self, api_key):
        """
        Constructor for the SecurityTrailsAPI class.

        Note: Some of the function calls can only be used by accounts with a subscription.
        This functions are marked as 'Experimental'. These endpoints have not been completely
        tested using this wrapper due to a lack of a subscription.

        :param api_key: The api key given after setting up an account on Security Trails
        :type api_key: str, required 
        """

        self.key = api_key
        self.base_api_url = "https://api.securitytrails.com/v1/"
        self.headers = {"apikey": self.key, "Content-Type": "application/json"}

    def explore_ips(self, ipaddress):
        """
        Returns the neighbors in any given IP level range and allows you to explore
        closeby IP addresses.

        :param ipaddress: The ipaddress/range you wish to find neighbours for.
        :type ipaddress: str, required

        :return: A dict formatted response from the Security Trails API.
        :rtype: dict
        """

        explore_ips_endpoint = self.base_api_url + "ips/nearby/{}".format(ipaddress)
        explore_ips_response = requests.get(explore_ips_endpoint, headers=self.headers)
        if explore_ips_response.raise_for_status():
            raise Exception(self._return_error(explore_ips_response.status_code))
        return explore_ips_response.json()

    def feeds_domains(self, record_type, search_filter, tld, ns, date):
        """
        Fetch zone files including authoritative nameservers.

        :param record_type: Valid domain values are "all", "dropped", "new" or "registered"
        :type record_type: str, required
        :param search_filter: Valid filter values are "cctld" and "gtld"
        :type search_filter: str, optional
        :param tld: Can be used to only return domains of a specific tld, such as "com"
        :type tld: str, optional
        :param ns: Show nameservers in the list.
        :type ns: bool, optional
        :param date: Date to fetch data for, format YYYY-MM-DD, e.g. 2019-06-11. Default is today.
        :type date: str, option

        :return: A dict formatted response from the Security Trails API.
        :rtype: dict
        """

        path = "feeds/domains/{0}?filter={1}&tld={2}&ns={3}&date={4}".format(
            record_type, search_filter, tld, ns, date
        )
        print(path)
        find_domains_endpoint = self.base_api_url + path
        find_domains_response = requests.get(
            find_domains_endpoint, headers=self.headers
        )
        if find_domains_response.raise_for_status():
            raise Exception(self._return_error(find_domains_response.status_code))
        return find_domains_response.json()

    def find_associated_domains(self, domain, page):
        """
        Find all domains that are related to the given domain.

        :param domain: The domain to find associated domains for.
        :type domain: str, required
        :param page: The page of the returned results.
        :type page: int, optional

        :return: A dict formatted response from the Security Trails API.
        :rtype: dict
        """

        find_domains_endpoint = self.base_api_url + "domain/{}/associated?page={}".format(
            domain, page
        )
        find_domains_response = requests.get(
            find_domains_endpoint, headers=self.headers
        )
        if find_domains_response.raise_for_status():
            raise Exception(self._return_error(find_domains_response.status_code))
        return find_domains_response.json()

    def get_domain(self, domain):
        """
        Returns the current data about the given domain. In addition to the current data,
        you also get the current statistics associated with a particular record. For example,
        for A records you'll get how many other domains have the same IP.

        :param domain: The domain to find associated domains for.
        :type domain: str, required

        :return: A dict formatted response from the Security Trails API.
        :rtype: dict
        """

        get_domain_endpoint = self.base_api_url + "domain/" + domain
        get_domain_response = requests.get(get_domain_endpoint, headers=self.headers)
        if get_domain_response.raise_for_status():
            raise Exception(self._return_error(get_domain_endpoint.status_code))
        return get_domain_response.json()

    def get_whois(self, domain):
        """
        Returns the current WHOIS data about a given domain with the stats merged together.

        :param domain: The domain to find WHOIS data for.
        :type domain: str, required

        :return: A dict formatted response from the Security Trails API.
        :rtype: dict
        """

        get_whois_endpoint = self.base_api_url + "domain/{}/whois".format(domain)
        get_whois_response = requests.get(get_whois_endpoint, headers=self.headers)
        if get_whois_response.raise_for_status():
            raise Exception(self._return_error(get_whois_response.status_code))
        return get_whois_response.json()

    def history_by_domain(self, domain, page):
        """
        Returns historical WHOIS information about the given domain.

        :param domain: The domain to find historical WHOIS data for.
        :type domain: str, required
        :param page: The page of the returned results.
        :type page: int, optional

        :return: A dict formatted response from the Security Trails API.
        :rtype: dict
        """

        history_by_domain_endpoint = (
            self.base_api_url + "history/{}/whois?page={}".format(domain, page)
        )
        history_by_domain_response = requests.get(
            history_by_domain_endpoint, headers=self.headers
        )
        if history_by_domain_response.raise_for_status():
            raise Exception(self._return_error(history_by_domain_response.status_code))
        return history_by_domain_response.json()

    def history_by_record(self, domain, record_type, page):
        """
        Lists out specific historical information about the given hostname parameter.

        :param domain: The domain to find historical data for.
        :type domain: str, required
        :param record_type: The record type to search for. 
            Allowed values: a, aaaa, mx, ns, soa or txt
        :type record_type: str, required
        :param page: The page of the returned results.
        :type page: int, optional

        :return: A dict formatted response from the Security Trails API.
        :rtype: dict
        """

        history_by_record_endpoint = self.base_api_url + "history/{}/dns/{}?page={}".format(
            domain, record_type, page
        )
        history_by_record_response = requests.get(
            history_by_record_endpoint, headers=self.headers
        )
        if history_by_record_response.raise_for_status():
            raise Exception(self._return_error(history_by_record_response.status_code))
        return history_by_record_response.json()

    def ip_search_stats(self, query):
        """
        Lists out specific historical information about the given hostname parameter.

        :param query: The API query e.g. `ptr_part='amazon.com'`.
        :type query: str, required

        :return: A dict formatted response from the Security Trails API.
        :rtype: dict
        """

        ip_search_stats_endpoint = self.base_api_url + "domains/stats"
        ip_param = '{"query": ' + query + "}"
        ip_search_stats_response = requests.post(
            ip_search_stats_endpoint, headers=self.headers, data=ip_param
        )
        if ip_search_stats_response.raise_for_status():
            raise Exception(self._return_error(ip_search_stats_response.status_code))
        return ip_search_stats_response.json()

    def list_subdomains(self, domain):
        """
        Returns subdomains for a given hostname.

        :param domain: The domain to find subdomains for.
        :type domain: str, required

        :return: A dict formatted response from the Security Trails API.
        :rtype: dict
        """

        list_subdomains_endpoint = self.base_api_url + "domain/{}/subdomains".format(
            domain
        )
        list_subdomains_response = requests.get(
            list_subdomains_endpoint, headers=self.headers
        )
        if list_subdomains_response.raise_for_status():
            raise Exception(self._return_error(list_subdomains_response.status_code))
        return list_subdomains_response.json()

    def list_tags(self, domain):
        """
        Returns tags for a given hostname.

        :param domain: The domain to find tags for.
        :type domain: str, required

        :return: A dict formatted response from the Security Trails API.
        :rtype: dict
        """

        list_tags_endpoint = self.base_api_url + "domain/{}/tags".format(domain)
        list_tags_response = requests.get(list_tags_endpoint, headers=self.headers)
        if list_tags_response.raise_for_status():
            raise Exception(self._return_error(list_tags_response.status_code))
        return list_tags_response.json()

    def ping(self):
        """
        Use this function to test your authentication and access to the SecurityTrails API.

        :return: A dict formatted response from the Security Trails API.
        :rtype: dict
        """

        ping_endpoint = self.base_api_url + "ping"
        ping_response = requests.get(ping_endpoint, headers=self.headers)
        if ping_response.raise_for_status():
            raise Exception("Unable to connect to SecurityTrails API.")
        return ping_response.json()

    @staticmethod
    def _return_error(status_code):
        error_messages = {
            401: "Invalid SecurityTrails API key",
            429: "Too many requests. Wait and try again.",
            500: "An internal error occured.",
        }
        return error_messages[status_code]

    def search_domain_filter(self, search_filter, include_ips, page):
        """
        Filter and search specific records.

        :param search_filter: A search filter constructed from :class:`SecurityTrailsAPIFilter`.
        :type domain: SecurityTrailsAPIFilter, required
        :param include_ips: Resolves any A records and additionally returns IP addresses.
        :type include_ips: bool, optional
        :param page: The page of the returned results.
        :type page: int, optional

        :return: A dict formatted response from the Security Trails API.
        :rtype: dict
        """

        search_domain_filter_endpoint = (
            self.base_api_url
            + "domains/list?"
            + "include_ips={}&page={}".format(include_ips, page)
        )
        filter_param = '{"filter": ' + json.dumps(search_filter.__dict__) + "}"
        search_domain_filter_response = requests.post(
            search_domain_filter_endpoint, headers=self.headers, data=filter_param
        )
        if search_domain_filter_response.raise_for_status():
            raise Exception(
                self._return_error(search_domain_filter_response.status_code)
            )
        return search_domain_filter_response.json()

    def search_domain_dsl(self, query, include_ips, page, scroll):
        """
        Filter and search specific records using SecurityTrails DSL.

        :param query: A DSL query e.g. `whois_email='domain-contact@oracle.com'`.
        :type query: str, required
        :param include_ips: Resolves any A records and additionally returns IP addresses.
        :type include_ips: bool, optional
        :param page: The page of the returned results.
        :type page: int, optional
        :param scroll: Request scrolling.
            See `Scrolling API <https://docs.securitytrails.com/reference#scroll>`_ .
        :type scroll: bool, option

        :return: A dict formatted response from the Security Trails API.
        :rtype: dict
        """

        search_domain_dsl_endpoint = (
            self.base_api_url
            + "domains/list?"
            + "include_ips=%s&page=%s"
            + "&scroll=%s",
            include_ips,
            page,
            scroll,
        )
        query_param = '{"query": %s}', query
        search_domain_dsl_response = requests.post(
            search_domain_dsl_endpoint, headers=self.headers, data=query_param
        )
        if search_domain_dsl_response.raise_for_status():
            raise Exception(self._return_error(search_domain_dsl_response.status_code))
        return search_domain_dsl_response.json()

    def search_ips(self, query, page):
        """
        Search IP's using SecurityTrail's DSL.

        :param query: A DSL query e.g. `ptr_part='ns1'`.
        :type query: str, required
        :param page: The page of the returned results.
        :type page: int, optional

        :return: A dict formatted response from the Security Trails API.
        :rtype: dict
        """

        search_ips = self.base_api_url + "ips/list?&page={}".format(page)
        ip_params = '{"query": %s}', query
        search_ips_response = requests.post(
            search_ips, headers=self.headers, data=ip_params
        )
        if search_ips_response.raise_for_status():
            raise Exception(self._return_error(search_ips_response.status_code))
        return search_ips_response.json()

    def search_statistics(self, search_filter):
        """
        Search IP's using SecurityTrail's DSL.

        :param search_filter: A search filter constructed from :class:`SecurityTrailsAPIFilter`.
        :type domain: SecurityTrailsAPIFilter, required

        :return: A dict formatted response from the Security Trails API.
        :rtype: dict
        """

        search_statistics_endpoint = self.base_api_url + "domains/stats"
        filter_param = '{"filter": ' + json.dumps(search_filter.__dict__) + "}"
        search_statistics_response = requests.post(
            search_statistics_endpoint, headers=self.headers, data=filter_param
        )
        if search_statistics_response.raise_for_status():
            raise Exception(self._return_error(search_statistics_response.status_code))
        return search_statistics_response.json()

    def usage(self):
        """
        Return your current API usage stats.

        :return: A dict formatted response from the Security Trails API.
        :rtype: dict
        """

        usage_endpoint = self.base_api_url + "account/usage"
        usage_response = requests.get(usage_endpoint, headers=self.headers)
        if usage_response.raise_for_status():
            raise Exception(self._return_error(usage_response.status_code))
        return usage_response.json()


class SecurityTrailsAPIFilter:
    def __init__(self):
        """
        Constructor for the SecurityTrailsAPIFilter class.

        :param ipv4: IPv4 address
        :type ipv4: str, optional
        :param ipv6: IPv6 address
        :type ipv6: str, optional
        :param apex_domain: The apex domain
        :type apex_domain: str, optional
        :param keyword: Keyword to search for
        :type keyword: str, optional
        :param mx: MX record to search for
        :type mx: str, optional
        :param ns: NS record to search for
        :type ns: str, optional
        :param cname: Canonical name to search
        :type cname: str, optional
        :param subdomain: Subdomain to look for
        :type subdomain: str, optional
        :param soa_email: The SOA email to search for
        :type soa_email: str, optional
        :param tld: TLD to look for
        :type tld: str, optional
        :param whois_email: WHOIS email to look for
        :type whois_email: str, optional
        :param whois_street1: WHOIS Street 1
        :type whois_street1: str, optional
        :param whois_street2: WHOIS Street 2
        :type whois_street2: str, optional
        :param whois_street3: WHOIS Street 3
        :type whois_street3: str, optional
        :param whois_street4: WHOIS Street 4
        :type whois_street4: str, optional

        :param whois_telephone: WHOIS Telephone
        :type whois_telephone: str, optional
        :param whois_postalCode: WHOIS Postal Code
        :type whois_postalCode: str, optional
        :param whois_organization: WHOIS Organization
        :type whois_organization: str, optional
        :param whois_name: WHOIS Name
        :type whois_name: str, optional
        :param whois_fax: WHOIS Fax
        :type whois_fax: str, optional
        :param whois_city: WHOIS City
        :type whois_city: str, optional
        :param query: SecurityTrails DSL query.
        :type query: str, optional
        """
        self.ipv4 = ""
        self.ipv6 = ""
        self.apex_domain = ""
        self.keyword = ""
        self.mx = ""
        self.ns = ""
        self.cname = ""
        self.subdomain = ""
        self.soa_email = ""
        self.tld = ""
        self.whois_email = ""
        self.whois_street1 = ""
        self.whois_street2 = ""
        self.whois_street3 = ""
        self.whois_street4 = ""
        self.whois_telephone = ""
        self.whois_postalCode = ""
        self.whois_organization = ""
        self.whois_name = ""
        self.whois_fax = ""
        self.whois_city = ""
        self.query = ""
