import base64
import socket
import logging

import dns.message
import requests


class HTTPSOutbound:
    def __init__(self, domain, port, timeout, proxies, ip):
        self._domain = domain
        self._port = port
        self._timeout = timeout
        self._proxies = proxies
        self._ip = ip
        self.logger = logging.getLogger("encrypted_dns.HTTPSOutbound")

    @classmethod
    def from_dict(cls, outbound_dict):
        if outbound_dict['protocol'] != 'https' and outbound_dict['protocol'] != 'doh':
            raise Exception()

        ip = outbound_dict['ip']
        address = outbound_dict.get('domain', ip)
        proxies = outbound_dict.get('proxy', None)
        port = outbound_dict.get('port', 443)
        timeout = outbound_dict.get('timeout', 60)
        return cls(address, port, timeout, proxies, ip)

    def query(self, dns_message):
        query_message = dns_message.to_wire()
        base64_query_string = self.struct_query(query_message)
        query_headers = {'Host': self._domain}
        query_parameters = {'dns': base64_query_string, 'ct': 'application/dns-message'}

        try:
            with requests.Session() as https_connection:
                https_connection.proxies = self._proxies
                response = https_connection.get(
                    "https://{}:{}/dns-query".format(self._ip, self._port),
                    params=query_parameters,
                    headers=query_headers
                )
                if response.status_code == requests.codes.ok:
                    return dns.message.from_wire(response.content)
                else:
                    response.raise_for_status()

        except socket.timeout:
            self.logger.error('{}: socket timeout'.format(self._domain))
        except Exception:
            raise
        finally:
            https_connection.close()

    def query_json(self, dns_message):
        pass

    @staticmethod
    def struct_query(query_data):
        return base64.urlsafe_b64encode(query_data).decode("utf-8").strip("=")
