import socket
import ssl

from encrypted_dns.upstream import Upstream


class TLSUpstream(Upstream):
    def __init__(self, client_object, client_port, config, timeout):
        super().__init__(client_object, client_port, config, timeout)
        self.wrap_sock = None
        self.shake_hand()

    def shake_hand(self):
        super().shake_hand()

    def query(self, query_data):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            context.load_default_certs()
            with socket.create_connection((self.config['ip'], self.config['port']), timeout=self.timeout) as sock:
                self.wrap_sock = context.wrap_socket(sock, server_hostname=self.config['address'])
            query_data = "\x00".encode() + chr(len(query_data)).encode() + query_data
            self.wrap_sock.send(query_data)
            self.receive()
        except socket.timeout:
            print('[Error]', self.config['address'] + ': socket timeout.')

    def receive(self):
        try:
            self.wrap_sock.recv(2)
            query_result = self.wrap_sock.recv(1024)
            self.client_object.server.sendto(query_result, ('127.0.0.1', self.client_port))
        except socket.timeout:
            print('[Error]', self.config['address'] + ': socket timeout.')
