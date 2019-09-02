import base64
import socket
import ssl
import urllib.parse
import urllib.request


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
    def __init__(self, client, port, upstream_url, upstream_timeout, upstream_port=853):
        self.client = client
        self.port = port
        self.upstream_hostname = upstream_url
        self.upstream_port = upstream_port
        self.upstream_timeout = upstream_timeout

    def query(self, query_data):
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_default_certs()

        query_data = "\x00".encode() + chr(len(query_data)).encode() + query_data

        with socket.create_connection((self.upstream_hostname, 853), timeout=self.upstream_timeout) as sock:
            with context.wrap_socket(sock, server_hostname=self.upstream_hostname) as wrap_sock:
                print('version:', wrap_sock.version())
                wrap_sock.send(query_data)

                query_header = wrap_sock.recv(2)
                query_length = int.from_bytes(query_header[1:2], "big")

                query_result = wrap_sock.recv(query_length)
                print('query_result:', query_result)
                self.client.sendto(query_result, ('127.0.0.1', self.port))
                wrap_sock.close()


class HTTPSUpstream:
    def __init__(self, client, port, upstream_url, upstream_timeout):
        self.upstream_url = upstream_url
        self.upstream_timeout = upstream_timeout
        self.client = client
        self.port = port

    def query(self, query_data):
        base64_query_string = self.struct_query(query_data)
        base64_query_string = base64_query_string.replace('=', '')
        base64_query_string = base64_query_string.replace('+', '-')
        base64_query_string = base64_query_string.replace('/', '_')
        print('base64_query_string:', base64_query_string)

        query_parameters = urllib.parse.urlencode({'dns': base64_query_string, 'ct': 'application/dns-message'})
        query_url = self.upstream_url + '?' + query_parameters
        query_headers = {}
        query_request = urllib.request.Request(query_url, headers=query_headers)
        print('query_url:', query_url)

        response_data = urllib.request.urlopen(query_request, timeout=self.upstream_timeout)
        query_result = response_data.read()
        print('query_result:', query_result)

        self.client.sendto(query_result, ('127.0.0.1', self.port))

    @staticmethod
    def struct_query(query_data):
        base64_query_data = base64.b64encode(query_data)
        base64_query_string = base64_query_data.decode("utf-8")

        return base64_query_string
