import socket

from encrypted_dns import parse, upstream


class Server:

    def __init__(self, ip="0.0.0.0", port=10053):
        self.ip = ip
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.dns_map = {}

    def start(self):
        self.server.bind((self.ip, self.port))

        while True:
            recv_data, recv_address = self.server.recvfrom(512)
            recv_header = parse.ParseHeader.parse_header(recv_data)
            print('recv_data:', recv_data)

            transaction_id = recv_header['transaction_id']
            print('transaction_id:', transaction_id)

            if recv_header['flags']['QR'] == '0':
                self.dns_map[transaction_id] = recv_address
                self.handle_query(recv_data)

            if recv_header['flags']['QR'] == '1':
                if transaction_id in self.dns_map:
                    sendback_address = self.dns_map[transaction_id]
                    self.server.sendto(recv_data, sendback_address)
                    self.dns_map.pop(transaction_id)
                else:
                    pass

                self.handle_response(recv_data)

    def _send(self, response_data, address):
        self.server.sendto(response_data, address)

    def handle_query(self, query_data):
        query_parser = parse.ParseQuery(query_data)
        parse_result = query_parser.parse_plain()
        print('parse_result:', parse_result)

        # https_upstream = upstream.HTTPSUpstream(self.server, self.port, 'https://1.1.1.1/dns-query?')
        # https_upstream.query(query_data)
        # plain_upstream = upstream.PlainUpstream(self.server, self.port, '1.1.1.1')
        # plain_upstream.query(query_data)

        tls_upstream = upstream.TLSUpstream(self.server, self.port, 'dns.google')
        tls_upstream.query(query_data)

    @staticmethod
    def handle_response(self):
        pass

