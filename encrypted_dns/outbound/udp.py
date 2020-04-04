from abc import ABC

import dns.message
import dns.query

from encrypted_dns.outbound import BaseOutbound


class DatagramOutbound(BaseOutbound, ABC):
    def __init__(self, ip, port, timeout):
        super().__init__()
        self.ip = ip
        self.port = port
        self.timeout = timeout

    @classmethod
    def from_dict(cls, outbound_dict):
        super()
        if outbound_dict['protocol'] is not 'udp':
            raise Exception()
        ip = outbound_dict['ip']
        port = outbound_dict.get('port', 53)
        timeout = outbound_dict.get('timeout', 60)
        return cls(ip, port, timeout)

    def query(self, dns_message):
        response = dns.query.udp(dns_message, self.ip, port=self.port, timeout=self.timeout)
        return response

