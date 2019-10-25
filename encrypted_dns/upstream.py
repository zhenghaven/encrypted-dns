import base64
import http.client
import socket
import ssl


class PlainUpstream:
    def __init__(self, client, upstream_ip, upstream_timeout, upstream_port=53):
        self.upstream_ip = upstream_ip
        self.upsream_port = upstream_port
        self.client = client
        self.upstream_timeout = upstream_timeout

    def query(self, query_data):
        self.send(query_data)

    def send(self, message_data):
        self.client.settimeout(self.upstream_timeout)
        self.client.sendto(message_data, (self.upstream_ip, self.upsream_port))
        self.client.settimeout(socket.getdefaulttimeout())


class TLSUpstream:
    def __init__(self, client, port, item, timeout):
        self.client = client
        self.port = port
        self.item = item
        self.timeout = timeout

    def query(self, query_data):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            context.load_default_certs()
            with socket.create_connection((self.item['ip'], self.item['port']), timeout=self.timeout) as sock:
                wrap_sock = context.wrap_socket(sock, server_hostname=self.item['address'])

            query_data = "\x00".encode() + chr(len(query_data)).encode() + query_data
            wrap_sock.send(query_data)

            query_header = wrap_sock.recv(2)
            query_length = int.from_bytes(query_header[1:2], "big")

            query_result = wrap_sock.recv(query_length)
            self.client.sendto(query_result, ('127.0.0.1', self.port))

        except socket.timeout:
            print('[Error]', self.item['address'] + ': socket timeout.')


class HTTPSUpstream:
    def __init__(self, client, port, item, timeout):
        self.client = client
        self.port = port
        self.item = item
        self.upstream_url = item['address']
        self.timeout = timeout

    def query(self, query_data):
        base64_query_string = self.struct_query(query_data)
        base64_query_string = base64_query_string.replace('=', '')
        base64_query_string = base64_query_string.replace('+', '-')
        base64_query_string = base64_query_string.replace('/', '_')

        query_parameters = '?dns=' + base64_query_string + '&ct=application/dns-message'
        query_url = '/dns-query' + query_parameters
        query_headers = {'host': self.upstream_url}
        self.receive(query_url, query_headers)

    def receive(self, query_url, query_headers):
        try:
            https_connection = http.client.HTTPSConnection(self.item['ip'], self.item['port'], timeout=self.timeout)
            https_connection.request('GET', query_url, headers=query_headers)
            response_object = https_connection.getresponse()
            query_result = response_object.read()
            self.client.sendto(query_result, ('127.0.0.1', self.port))
        except socket.timeout:
            print('[Error]', self.item['address'] + ': socket timeout.')

    @staticmethod
    def struct_query(query_data):
        base64_query_data = base64.b64encode(query_data)
        base64_query_string = base64_query_data.decode("utf-8")

        return base64_query_string
