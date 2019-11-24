import base64
import http.client
import socket

from encrypted_dns.upstream import Upstream


class HTTPSUpstream(Upstream):
    def __init__(self, client_object, client_port, config, timeout):
        super().__init__(client_object, client_port, config, timeout)
        self.query_url = None
        self.query_headers = None
        self.shake_hand()

    def shake_hand(self):
        super().shake_hand()

    def query(self, query_data):
        base64_query_string = self.struct_query(query_data)
        query_parameters = '?dns=' + base64_query_string + '&ct=application/dns-message'
        self.query_url = '/dns-query' + query_parameters
        self.query_headers = {'host': self.config["address"]}
        self.receive()

    def receive(self):
        try:
            if self.config['enable_http_proxy']:
                https_connection = http.client.HTTPSConnection(self.config['proxy_host'],
                                                               self.config['proxy_port'], timeout=self.timeout)
                https_connection.set_tunnel(self.config['ip'], self.config['port'])
            else:
                https_connection = http.client.HTTPSConnection(self.config['ip'],
                                                               self.config['port'], timeout=self.timeout)

            https_connection.request('GET', self.query_url, headers=self.query_headers)
            response_object = https_connection.getresponse()
            query_result = response_object.read()
            self.client_object.server.sendto(query_result, ('127.0.0.1', self.client_port))
        except socket.timeout:
            print('[Error]', self.config['address'] + ': socket timeout.')

    @staticmethod
    def struct_query(query_data):
        base64_query_data = base64.urlsafe_b64encode(query_data)
        base64_query_string = base64_query_data.decode("utf-8")
        return base64_query_string
