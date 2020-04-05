import dns.query

from encrypted_dns.outbound import BaseOutbound


class StreamOutbound(BaseOutbound):
    def __init__(self, ip, port, timeout):
        super().__init__()
        self.ip = ip
        self.port = port
        self.timeout = timeout

    @classmethod
    def from_dict(cls, outbound_dict):
        super()
        if outbound_dict['protocol'] is not 'tcp':
            raise Exception()
        ip = outbound_dict['ip']
        port = outbound_dict.get('port', 53)
        timeout = outbound_dict.get('timeout', 60)
        return cls(ip, port, timeout)

    def query(self, dns_message):
        return dns.query.tcp(dns_message, self.ip, port=self.port, timeout=self.timeout)
