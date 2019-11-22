from abc import ABC, abstractmethod
import socket


class BaseServer(ABC):
    def __init__(self, server_config, controller_address):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_config = server_config
        self.server.bind((self.server_config['address'], self.server_config['port']))
        self.controller_address = controller_address
        self.dns_map = {}

    @abstractmethod
    def start(self):
        pass

    @abstractmethod
    def query(self, query_data):
        pass

    @abstractmethod
    def response(self, response_data, address):
        pass
