import random
import socket
import threading
import time

from encrypted_dns import parse, upstream, utils, struct, log


class Server:

    def __init__(self, dns_config_object):
        self.dns_config = dns_config_object.get_config()
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.dns_map = self.cache = {}
        self.upstream_object = {'https': {}, 'tls': {}}
        self.enable_log = self.dns_config['enable_log']
        self.enable_cache = self.dns_config['enable_cache']
        self.server.bind((self.dns_config['listen_address'], self.dns_config['listen_port']))
        print('DNS server listening on:', self.dns_config['listen_address'] + ':' + str(self.dns_config['listen_port']))
        bootstrap_dns_address = self.dns_config['bootstrap_dns_address']['address']
        bootstrap_dns_port = self.dns_config['bootstrap_dns_address']['port']
        upstream_timeout = self.dns_config['upstream_timeout']
        self.bootstrap_dns_object = upstream.PlainUpstream(self.server, bootstrap_dns_address,
                                                           upstream_timeout, bootstrap_dns_port)
        self.check_config()

        if self.enable_log:
            self.logger = log.Logger()
            self.logger.create_log()

    def check_config(self):
        for item in self.dns_config['upstream_dns']:
            protocol = item['protocol']
            address = item['address']
            if protocol == 'https' or protocol == 'tls':
                if not utils.is_valid_ipv4_address(address):
                    if 'ip' not in item or item['ip'] == '':
                        item['ip'] = self.get_ip_address(address, self.bootstrap_dns_object)

                self.upstream_object[protocol][address] = self.shake_hand(item)

    def shake_hand(self, item):
        if item['protocol'] == 'https':
            https_upstream = upstream.HTTPSUpstream(self.server, self.dns_config['listen_port'],
                                                    item, self.dns_config['upstream_timeout'])
            return https_upstream

        if item['protocol'] == 'tls':
            tls_upstream = upstream.TLSUpstream(self.server, self.dns_config['listen_port'],
                                                item, self.dns_config['upstream_timeout'])
            return tls_upstream

    def start(self):
        while True:
            recv_data, recv_address = self.server.recvfrom(512)
            recv_header = parse.ParseHeader.parse_header(recv_data)
            if self.enable_log:
                self.logger.write_log('recv_data:' + str(recv_data))

            transaction_id = recv_header['transaction_id']
            if self.enable_log:
                self.logger.write_log('transaction_id:' + str(transaction_id))

            if recv_header['flags']['QR'] == '0':
                if recv_address[0] not in self.dns_config['client_blacklist']:
                    self.dns_map[transaction_id] = recv_address
                    query_thread = threading.Thread(target=self.handle_query, args=(transaction_id, recv_data,))
                    query_thread.daemon = True
                    query_thread.start()

            if recv_header['flags']['QR'] == '1':
                if self.enable_cache:
                    response = self.handle_response(recv_data)
                    if response[2]:
                        response_name = utils.get_domain_name_string(response[2][0]['domain_name'])
                        if response_name != '':
                            response_type = response[2][0]['type']
                            response_ttl = response[2][0]['ttl']
                            if response_name not in self.cache:
                                self.cache[response_name] = {}
                            self.cache[response_name][response_type] = [recv_data, int(time.time()), response_ttl]

                if transaction_id in self.dns_map:
                    sendback_address = self.dns_map[transaction_id]
                    self.server.sendto(recv_data, sendback_address)
                    self.dns_map.pop(transaction_id)
                else:
                    pass

    def _send(self, response_data, address):
        self.server.sendto(response_data, address)

    def handle_query(self, transaction_id, query_data):
        try:
            query_parser = parse.ParseQuery(query_data)
            parse_result = query_parser.parse_plain()
            query_name_list = parse_result[1]['QNAME']
            query_type = parse_result[1]['QTYPE']
            query_name = utils.get_domain_name_string(query_name_list)

            if self.enable_log:
                self.logger.write_log('query_parse_result:' + str(parse_result))

            cache_query = None
            cached = False

            if self.enable_cache and query_name in self.cache and query_type in self.cache[query_name]:
                cache_query = self.cache[query_name][query_type]
                cache_time = cache_query[1]
                cache_ttl = cache_query[2]
                current_time = int(time.time())

                if current_time - cache_time > cache_ttl:
                    self.cache[query_name].pop(query_type)
                else:
                    cached = True

            if cached:
                cache_query_result = cache_query[0]

                cache_query_result = bytes.fromhex(transaction_id) + cache_query_result[2:]
                sendback_address = self.dns_map[transaction_id]
                self.server.sendto(cache_query_result, sendback_address)
                self.dns_map.pop(transaction_id)
            else:
                if query_name in self.dns_config['dns_bypass']:
                    upstream_object = self.bootstrap_dns_object
                else:
                    upstream_object = self.select_upstream()

                upstream_object.query(query_data)

        except IndexError as exc:
            print('[Error]', str(exc))
        except BaseException as exc:
            print('[Error]', str(exc))

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
            upstream_object = self.upstream_object['https'][address]
        elif protocol == 'tls':
            upstream_object = self.upstream_object['tls'][address]

        return upstream_object

    def handle_response(self, response_data):
        response_parser = parse.ParseResponse(response_data)
        parse_result = response_parser.parse_plain()
        if self.enable_log:
            self.logger.write_log('response_parse_result:' + str(parse_result))
        return parse_result

    def get_ip_address(self, address, bootstrap_dns_object):
        try:
            query_structer = struct.StructQuery(address)
            query_data, transaction_id = query_structer.struct()
            self.dns_map[transaction_id] = address

            bootstrap_dns_object.query(query_data)
            while True:
                recv_data, recv_address = self.server.recvfrom(512)
                recv_header = parse.ParseHeader.parse_header(recv_data)
                if recv_header['flags']['QR'] == '1' and recv_header['transaction_id'] in self.dns_map \
                        and self.dns_map[recv_header['transaction_id']] == address:
                    response = self.handle_response(recv_data)
                    address = response[2][0]['record']
                    return address

        except BaseException as exc:
            print('[Error]', str(exc))
            if address == 'dns.google' or address == 'dns.google.com':
                return '8.8.4.4'
            elif address == '1.1.1.1' or address == '1.0.0.1' or 'cloudflare-dns.com' in address:
                return '1.0.0.1'
            elif address == 'dns.quad9.net':
                return '9.9.9.9'
