import base64
import http.client
import socket

import dns.message

from encrypted_dns.outbound import BaseOutbound


class HTTPSOutbound(BaseOutbound):
    def __init__(self, domain, port, timeout, proxies, ip):
        super().__init__()
        self._domain = domain
        self._port = port
        self._timeout = timeout
        self._proxies = proxies
        self._ip = ip

    @classmethod
    def from_dict(cls, outbound_dict):
        super()
        if outbound_dict['protocol'] != 'https' and outbound_dict['protocol'] != 'doh':
            raise Exception()

        address = outbound_dict['domain']
        ip = outbound_dict['ip']

        # proxies = {
        #  "http": “http://10.10.10.10:8000”,
        #  "https": “https://user:pass@10.10.10.10:8000”,
        # }
        proxies = outbound_dict.get('proxies', None)
        port = outbound_dict.get('port', 443)
        timeout = outbound_dict.get('timeout', 60)
        return cls(address, port, timeout, proxies, ip)

    def query(self, dns_message):
        # with requests.sessions.Session() as session:
        #     session.proxies = self._proxies
        #     return dns.query.https(dns_message, self._address, port=self._port,
        #                            timeout=self._timeout, session=session)
        query_message = dns_message.to_wire()
        base64_query_string = self.struct_query(query_message)
        query_parameters = '?dns=' + base64_query_string + '&ct=application/dns-message'
        query_url = '/dns-query' + query_parameters
        query_headers = {'Host': self._domain}

        try:
            https_connection = http.client.HTTPSConnection(self._ip, self._port, timeout=self._timeout)
            https_connection.request('GET', query_url, headers=query_headers)
            response_object = https_connection.getresponse()
            return dns.message.from_wire(response_object.read())

        except socket.timeout:
            print('[Error] {}: socket timeout'.format(self._domain))

    @staticmethod
    def struct_query(query_data):
        base64_query_string = base64.urlsafe_b64encode(query_data).decode("utf-8").strip("=")
        return base64_query_string
