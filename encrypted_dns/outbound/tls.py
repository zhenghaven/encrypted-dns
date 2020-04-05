import dns.query

from encrypted_dns.outbound import BaseOutbound


class TLSOutbound(BaseOutbound):
    def __init__(self, address, port, timeout):
        super().__init__()
        self.address = address
        self.port = port
        self.timeout = timeout

    @classmethod
    def from_dict(cls, outbound_dict):
        super()
        if outbound_dict['protocol'] not in {'tls', 'dot'}:
            raise Exception()
        if 'ip' in outbound_dict:
            address = outbound_dict['ip']
        elif 'domain' in outbound_dict:
            address = outbound_dict['domain']
        else:
            raise Exception()

        port = outbound_dict.get('port', 443)
        timeout = outbound_dict.get('timeout', 60)
        return cls(address, port, timeout)

    def query(self, dns_message):
        return dns.query.tls(dns_message, self.address, port=self.port, timeout=self.timeout)
