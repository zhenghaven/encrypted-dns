from abc import ABC, abstractmethod


class BaseServer(ABC):
    def __init__(self, server_config, controller_address):
        self.server_config = server_config
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
