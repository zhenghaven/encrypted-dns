import socket
import encrypted_dns


class Server:

    def __init__(self, ip='127.0.0.1', port=53):
        self.ip = ip
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def start(self):
        self.server.bind((self.ip, self.port))

        while True:
            query_data, address = self.server.recvfrom(512)
            self.handel_query(query_data)

    def _send(self, response_data, address):
        self.server.sendto(response_data, address)

    def handel_query(self, query_data):
        query_parser = encrypted_dns.ParseQuery(query_data)
