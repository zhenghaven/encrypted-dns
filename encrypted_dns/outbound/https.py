import requests

import dns.query

from encrypted_dns.outbound import BaseOutbound


class HTTPSOutbound(BaseOutbound):
    def __init__(self, address, port, timeout, proxies):
        super().__init__()
        self._address = address
        self._port = port
        self._timeout = timeout
        self._proxies = proxies

    @classmethod
    def from_dict(cls, outbound_dict):
        super()
        if outbound_dict['protocol'] != 'https' and outbound_dict['protocol'] != 'doh':
            raise Exception()
        if 'ip' in outbound_dict:
            address = outbound_dict['ip']
        elif 'domain' in outbound_dict:
            address = outbound_dict['domain']
        else:
            raise Exception()

        # proxies = {
        #  "http": “http://10.10.10.10:8000”,
        #  "https": “https://user:pass@10.10.10.10:8000”,
        # }
        proxies = outbound_dict.get('proxies', None)
        port = outbound_dict.get('port', 443)
        timeout = outbound_dict.get('timeout', 60)
        return cls(address, port, timeout, proxies)

    def query(self, dns_message):
        with requests.sessions.Session() as session:
            # q, where, timeout=None, port=443, af=None, source=None, source_port=0,
            # one_rr_per_rrset=False, ignore_trailing=False,
            # session=None, path='/dns-query', post=True,
            # bootstrap_address=None, verify=True
            session.proxies = self._proxies
            return dns.query.https(dns_message, self._address, port=self._port,
                                   timeout=self._timeout, session=session)
