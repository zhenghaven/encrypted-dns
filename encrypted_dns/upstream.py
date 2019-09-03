import base64
import socket
import http.client


class PlainUpstream:
    def __init__(self, client, upstream_ip, upstream_timeout, upstream_port=53):
        self.upstream_ip = upstream_ip
        self.upsream_port = upstream_port
        self.client = client
        self.upstream_timeout = upstream_timeout

    def query(self, query_data):
        self._send(query_data)

    def _send(self, message_data):
        self.client.settimeout(self.upstream_timeout)
        self.client.sendto(message_data, (self.upstream_ip, self.upsream_port))
        self.client.settimeout(socket.getdefaulttimeout())


class TLSUpstream:
    def __init__(self, client, port, wrap_sock):
        self.client = client
        self.port = port
        self.wrap_sock = wrap_sock

    def query(self, query_data):
        query_data = "\x00".encode() + chr(len(query_data)).encode() + query_data
        print('version:', self.wrap_sock.version())
        self.wrap_sock.send(query_data)

        query_header = self.wrap_sock.recv(2)
        query_length = int.from_bytes(query_header[1:2], "big")

        query_result = self.wrap_sock.recv(query_length)
        print('query_result:', query_result)
        self.client.sendto(query_result, ('127.0.0.1', self.port))


class HTTPSUpstream:
    def __init__(self, client, port, upstream_url, https_connection):
        self.client = client
        self.port = port
        self.upstream_url = upstream_url
        self.https_connection = https_connection

    def query(self, query_data):
        base64_query_string = self.struct_query(query_data)
        base64_query_string = base64_query_string.replace('=', '')
        base64_query_string = base64_query_string.replace('+', '-')
        base64_query_string = base64_query_string.replace('/', '_')
        print('base64_query_string:', base64_query_string)

        query_parameters = '?dns=' + base64_query_string + '&ct=application/dns-message'
        query_url = '/dns-query' + query_parameters
        query_headers = {'host': self.upstream_url}
        self.https_connection.request('GET', query_url, headers=query_headers)
        response_object = self.https_connection.getresponse()
        query_result = response_object.read()
        print('query_result:', query_result)

        self.client.sendto(query_result, ('127.0.0.1', self.port))

    @staticmethod
    def struct_query(query_data):
        base64_query_data = base64.b64encode(query_data)
        base64_query_string = base64_query_data.decode("utf-8")

        return base64_query_string
