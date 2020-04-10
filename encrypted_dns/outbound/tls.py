import socket
import ssl

import dns.message

from encrypted_dns.outbound import BaseOutbound


class TLSOutbound(BaseOutbound):
    def __init__(self, domain, port, timeout, ip):
        super().__init__()
        self._domain = domain
        self._port = port
        self._timeout = timeout
        self._ip = ip

    @classmethod
    def from_dict(cls, outbound_dict):
        super()
        if outbound_dict['protocol'] != 'tls' and outbound_dict['protocol'] != 'dot':
            raise Exception()

        ip = outbound_dict['ip']
        domain = outbound_dict['domain']
        port = outbound_dict.get('port', 853)
        timeout = outbound_dict.get('timeout', 60)
        return cls(domain, port, timeout, ip)

    def query(self, dns_message):
        try:
            query_message = dns_message.to_wire()
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            context.load_default_certs()

            with socket.create_connection((self._ip, self._port), timeout=self._timeout) as sock:
                wrap_sock = context.wrap_socket(sock, server_hostname=self._domain)

            query_data = "\x00".encode() + chr(len(query_message)).encode() + query_message
            wrap_sock.send(query_data)
            wrap_sock.recv(2)
            return dns.message.from_wire(wrap_sock.recv(1024))

            # return dns.query.tls(dns_message, self._address, port=self._port, timeout=self._timeout)

        except socket.timeout:
            print('[Error] {}: socket timeout'.format(self._domain))

        except Exception as exc:
            print('[Error]', str(exc))
