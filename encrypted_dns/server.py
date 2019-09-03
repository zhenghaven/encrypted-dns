import random
import socket
import ssl
import http.client
from encrypted_dns import parse, upstream, utils, struct


class Server:

    def __init__(self, dns_config_object):
        self.dns_config = dns_config_object.get_config()
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.dns_map = {}
        self.upstream_shake_hand = {}

        self.server.bind((self.dns_config['listen_address'], self.dns_config['listen_port']))
        self.check_config()

    def check_config(self):
        bootstrap_dns_address = self.dns_config['bootstrap_dns_address']['address']
        bootstrap_dns_port = self.dns_config['bootstrap_dns_address']['port']

        for item in self.dns_config['upstream_dns']:
            if item['protocol'] == 'https' or item['protocol'] == 'tls':
                address = item['address']
                if not utils.is_valid_ipv4_address(address):
                    if 'ip' not in item or item['ip'] == '':
                        item['ip'] = self.get_ip_address(address, bootstrap_dns_address,
                                                         bootstrap_dns_port, self.dns_config['upstream_timeout'])

                self.upstream_shake_hand[address] = self.shake_hand(item)

    def shake_hand(self, item):
        if item['protocol'] == 'https':
            https_connection = http.client.HTTPSConnection(item['ip'], item['port'],
                                                           timeout=self.dns_config['upstream_timeout'])
            return https_connection

        if item['protocol'] == 'tls':
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            context.load_default_certs()
            with socket.create_connection((item['ip'], 853), timeout=self.dns_config['upstream_timeout']) as sock:
                wrap_sock = context.wrap_socket(sock, server_hostname=item['address'])
                return wrap_sock

    def start(self):
        while True:
            recv_data, recv_address = self.server.recvfrom(512)
            recv_header = parse.ParseHeader.parse_header(recv_data)
            print('recv_data:', recv_data)

            transaction_id = recv_header['transaction_id']
            print('transaction_id:', transaction_id)

            if recv_header['flags']['QR'] == '0':
                self.dns_map[transaction_id] = recv_address
                self.handle_query(recv_data)

            if recv_header['flags']['QR'] == '1':
                if transaction_id in self.dns_map:
                    sendback_address = self.dns_map[transaction_id]
                    self.server.sendto(recv_data, sendback_address)
                    self.dns_map.pop(transaction_id)
                else:
                    pass

                self.handle_response(recv_data)

    def _send(self, response_data, address):
        self.server.sendto(response_data, address)

    def handle_query(self, query_data):
        query_parser = parse.ParseQuery(query_data)
        parse_result = query_parser.parse_plain()
        print('query_parse_result:', parse_result)

        upstream_object = self.select_upstream()
        upstream_object.query(query_data)

    def select_upstream(self):
        upstream_dns_list = self.dns_config['upstream_dns']
        enable_weight = self.dns_config['upstream_weight']
        upstream_timeout = self.dns_config['upstream_timeout']
        weight_list = []

        if enable_weight:
            for item in upstream_dns_list:
                weight_list.append(item['weight'])
            upstream_dns = random.choices(population=upstream_dns_list, weights=weight_list, k=1)
            upstream_dns = upstream_dns[0]
        else:
            upstream_dns = random.choice(upstream_dns_list)

        server = self.server
        protocol = upstream_dns['protocol']
        address = upstream_dns['address']
        port = upstream_dns['port']
        upstream_object = None

        if protocol == 'plain':
            upstream_object = upstream.PlainUpstream(server, address, upstream_timeout, port)
        elif protocol == 'https':
            upstream_object = upstream.HTTPSUpstream(server, self.dns_config['listen_port'],
                                                     address, self.upstream_shake_hand[address])
        elif protocol == 'tls':
            upstream_object = upstream.TLSUpstream(server, self.dns_config['listen_port'],
                                                   self.upstream_shake_hand[address])

        return upstream_object

    @staticmethod
    def handle_response(response_data):
        response_parser = parse.ParseResponse(response_data)
        parse_result = response_parser.parse_plain()
        print('response_parse_result:', parse_result)
        return parse_result

    def get_ip_address(self, address, bootstrap_dns_address, bootstrap_dns_port, upstream_timeout):
        query_structer = struct.StructQuery(address)
        query_data, transaction_id = query_structer.struct()
        self.dns_map[transaction_id] = address
        upstream_object = upstream.PlainUpstream(self.server, bootstrap_dns_address,
                                                 upstream_timeout, bootstrap_dns_port)
        upstream_object.query(query_data)
        while True:
            recv_data, recv_address = self.server.recvfrom(512)
            recv_header = parse.ParseHeader.parse_header(recv_data)
            if recv_header['flags']['QR'] == '1' and recv_header['transaction_id'] in self.dns_map \
                    and self.dns_map[recv_header['transaction_id']] == address:
                response = self.handle_response(recv_data)
                address = response[2][0]['record']
                return address
