import socket

from encrypted_dns import parse, utils
from encrypted_dns.server import BaseServer


class UDPServer(BaseServer):
    def __init__(self, server_config, controller_address):
        super().__init__(server_config, controller_address)

        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind((self.server_config['address'], self.server_config['port']))
        print('Plain DNS Server listening on:',
              self.server_config['address'] + ':' + str(self.server_config['port']))

    def start(self):
        while True:
            recv_data, recv_address = self.server.recvfrom(512)
            recv_header = parse.ParseHeader.parse_header(recv_data)
            transaction_id = recv_header['transaction_id']

            if recv_header['flags']['QR'] == '0' and not utils.is_subnet_address(self.server_config['client_blacklist'],
                                                                                 recv_address[0]):
                self.dns_map[transaction_id] = recv_address
                self.query(recv_data)

            elif recv_header['flags']['QR'] == '1' and transaction_id in self.dns_map:
                self.response(recv_data, self.dns_map[transaction_id])

            else:
                continue

    def query(self, query_data):
        self.server.sendto(query_data, self.controller_address)

    def response(self, response_data, address):
        self.server.sendto(response_data, address)
