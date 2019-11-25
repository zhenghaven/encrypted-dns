import socket

from encrypted_dns.upstream import Upstream


class TCPUpstream(Upstream):
    def __init__(self, client_object, client_port, config, timeout):
        super().__init__(client_object, client_port, config, timeout)
        self.tcp_socket = None
        self.shake_hand()

    def shake_hand(self):
        try:
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_socket.settimeout(self.timeout)
            self.tcp_socket.connect((self.config["address"], self.config["port"]))

        except socket.timeout:
            print('[Error]', self.config['address'] + ': socket timeout.')

        except Exception as exc:
            print('[Error]', str(exc))

    def query(self, query_data):
        try:
            query_data = "\x00".encode() + chr(len(query_data)).encode() + query_data
            self.tcp_socket.send(query_data)
            self.receive()

        except socket.timeout:
            print('[Error]', self.config['address'] + ': socket timeout.')

        except Exception as exc:
            print('[Error]', str(exc))

    def receive(self):
        try:
            self.tcp_socket.recv(2)
            query_result = self.tcp_socket.recv(1024)
            self.client_object.server.sendto(query_result, ('127.0.0.1', self.client_port))
            self.tcp_socket.close()

        except socket.timeout:
            print('[Error]', self.config['address'] + ': socket timeout.')

        except Exception as exc:
            print('[Error]', str(exc))
