import ssl
import socket

from encrypted_dns import parse
from encrypted_dns.server import BaseServer


class TLSServer(BaseServer):
    def __init__(self, server_config, controller_address):
        super().__init__(server_config, controller_address)

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.server_config['address'], self.server_config['port']))

        self.tls_server = ssl.wrap_socket(self.server, ssl_version=ssl.PROTOCOL_SSLv23, cert_reqs=ssl.CERT_NONE,
                                          server_side=True, keyfile=self.server_config['key'],
                                          certfile=self.server_config['cert'])

        print('DNS-over-TLS Server listening on:',
              self.server_config['address'] + ':' + str(self.server_config['port']))

    # def start(self):
    #     while True:
    #         recv_data, recv_address = self.server.recvfrom(4096)
    #         recv_header = parse.ParseHeader.parse_header(recv_data)
    #         transaction_id = recv_header['transaction_id']
    #
    #         if recv_header['flags']['QR'] == '0' and recv_address[0] not in self.server_config['client_blacklist']:
    #             self.dns_map[transaction_id] = recv_address
    #             self.query(recv_data)
    #
    #         elif recv_header['flags']['QR'] == '1' and transaction_id in self.dns_map:
    #             self.response(recv_data, self.dns_map[transaction_id])
    #
    #         else:
    #             continue

    def query(self, query_data):
        self.server.sendto(query_data, self.controller_address)

    def response(self, response_data, address):
        self.server.sendto(response_data, address)
