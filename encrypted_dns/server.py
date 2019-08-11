import socket

from encrypted_dns import parse


class Server:

    def __init__(self, ip='127.0.0.1', port=10053):
        self.ip = ip
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def start(self):
        self.server.bind((self.ip, self.port))

        while True:
            query_data, address = self.server.recvfrom(512)
            print(query_data)
            self.handel_query(query_data)

    def _send(self, response_data, address):
        self.server.sendto(response_data, address)

    @staticmethod
    def handel_query(query_data):
        query_parser = parse.ParseQuery(query_data)
        parse_result = query_parser.parse_plain()
        print(parse_result)
