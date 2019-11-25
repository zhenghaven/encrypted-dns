from abc import ABC, abstractmethod

from encrypted_dns import utils


class Upstream(ABC):
    def __init__(self, client_object, client_port, config, timeout):
        self.client_object = client_object
        self.client_port = client_port
        self.config = config
        self.timeout = timeout

    @abstractmethod
    def shake_hand(self):
        address = self.config['address']
        if ('ip' not in self.config or self.config['ip'] == '') and not utils.is_valid_ipv4_address(address):
            self.config['ip'] = utils.get_ip_address(self.client_object, address,
                                                     self.client_object.bootstrap_dns_object)

    @abstractmethod
    def query(self, query_data):
        pass

    @abstractmethod
    def receive(self):
        pass
