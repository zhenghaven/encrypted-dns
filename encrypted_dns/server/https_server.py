import http.server
import ssl
import base64

from encrypted_dns import parse
from encrypted_dns.server import BaseServer


class DNSOverHttpsHandler(http.server.SimpleHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(400)
        self.end_headers()

    def do_GET(self):
        if "/dns-query?dns=" in self.path:
            dns_message = self.path.replace("/dns-query?dns=", "")
        else:
            self.send_response(400)
            self.end_headers()
            return

        dns_message_decoded = base64.urlsafe_b64decode(dns_message)

        # return http.server.SimpleHTTPRequestHandler.do_GET(self)


class HTTPSServer(BaseServer):
    def __init__(self, server_config, controller_address):
        super().__init__(server_config, controller_address)

        server_address = (self.server_config['address'], self.server_config['port'])
        self.httpd = http.server.ThreadingHTTPServer(server_address, DNSOverHttpsHandler)
        self.httpd.socket = ssl.wrap_socket(self.httpd.socket, server_side=True, certfile=self.server_config['cert'],
                                            keyfile=self.server_config['key'], ssl_version=ssl.PROTOCOL_SSLv23)

        print('DNS-over-HTTPS Server listening on:',
              self.server_config['address'] + ':' + str(self.server_config['port']))

    def start(self):
        self.httpd.serve_forever()

        # while True:
        #     recv_data, recv_address = self.server.recvfrom(4096)
        #     recv_header = parse.ParseHeader.parse_header(recv_data)
        #     transaction_id = recv_header['transaction_id']
        #
        #     if recv_header['flags']['QR'] == '0' and recv_address[0] not in self.server_config['client_blacklist']:
        #         self.dns_map[transaction_id] = recv_address
        #         self.query(recv_data)
        #
        #     elif recv_header['flags']['QR'] == '1' and transaction_id in self.dns_map:
        #         self.response(recv_data, self.dns_map[transaction_id])
        #
        #     else:
        #         continue

    def query(self, query_data):
        pass
        # self.server.sendto(query_data, self.controller_address)

    def response(self, response_data, address):
        pass
        # self.server.sendto(response_data, address)
