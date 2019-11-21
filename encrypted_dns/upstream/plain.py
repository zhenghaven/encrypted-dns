import socket

from encrypted_dns.upstream import Upstream


class PlainUpstream(Upstream):
    def __init__(self, client_object, client_port, config, timeout):
        super().__init__(client_object, client_port, config, timeout)

    def shake_hand(self):
        pass

    def query(self, query_data):
        self.client_object.server.settimeout(self.timeout)
        self.client_object.server.sendto(query_data, (self.config["ip"], self.config["port"]))
        self.client_object.server.settimeout(socket.getdefaulttimeout())

    def receive(self):
        pass
