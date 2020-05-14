import concurrent.futures
import random
import time

import dns.dnssec
import dns.edns
import dns.flags
import dns.message
import dns.rdatatype

import encrypted_dns.outbound


class OutboundHandler:
    @staticmethod
    def get_group(query_name, domain_group, tag_group, rules=None):
        tag = encrypted_dns.utils.parse_domain_rules(domain_group, query_name, default='bootstrap')
        return tag_group[tag], tag_group[tag].get('concurrent', False)

    @staticmethod
    def random_outbound(outbounds):
        """Get a random outbound from the list of outbounds specified in config.json.

        :param outbounds: List of outbounds.
        :return: Dictionary of outbound and type of outbound
        """
        population = []
        for outbound in outbounds['dns']:
            population.append(outbound)
        return random.choice(population)

    @staticmethod
    def resolve_outbound_ip(outbound_address, bootstrap_dns_ip, hosts_dict):
        """Resolve ip address of HTTPS or TLS outbound with bootstrap dns address.

        :param hosts_dict: Dict of hosts to resolve IP address.
        :param outbound_address: Domain name of HTTPS or TLS outbound
        :param bootstrap_dns_ip: DNS server for resolving 'outbound_address'
        :return: RRSet Answer of HTTPS or TLS outbound
        """
        if outbound_address in hosts_dict:
            return hosts_dict[outbound_address]
        dns_query = dns.message.make_query(outbound_address, dns.rdatatype.A)
        response = dns.query.udp(dns_query, bootstrap_dns_ip)
        if response.answer:
            return response.answer[-1].items[0].to_text()


class WireMessageHandler:
    def __init__(self, outbounds, cache_object, ecs_ip_address, hosts, dnssec, firewall):
        self.cache = cache_object
        self.ecs_ip_address = ecs_ip_address
        self.hosts = hosts
        self.dnssec = dnssec
        self.firewall = firewall
        self.rate_per_second = [0, int(time.time())]

        # map protocol of outbound to the method for resolve
        self.protocol_methods = {
            'udp': WireMessageHandler._udp_resolve,
            'tcp': WireMessageHandler._tcp_resolve,
            'tls': WireMessageHandler._tls_resolve,
            'dot': WireMessageHandler._tls_resolve,
            'https': WireMessageHandler._https_resolve,
            'doh': WireMessageHandler._https_resolve,
        }

        self.tag_group = {}  # tag to group dict
        self.domain_group = {}  # domain to tag
        for dns_group in outbounds:
            self.tag_group[dns_group['tag']] = dns_group
            for domain in dns_group.get('domains', {}):
                self.domain_group[domain] = dns_group['tag']

    @staticmethod
    def edns_subnet_client(query_message, ip):
        """Add edns subnet client option to query messages.

        :param query_message: DNS query message for processing.
        :param ip: IP Address to add as an option.
        :return: Processed DNS query message.
        """
        if ip != '' and ip is not None:
            query_message.use_edns(0, 0, options=[dns.edns.ECSOption(ip)])

    def validate_dnssec(self, question_name, outbound, protocol):
        request = dns.message.make_query(question_name + '.', dns.rdatatype.DNSKEY, want_dnssec=True)
        response = self.protocol_methods[protocol].__call__(request, outbound)
        if response.rcode() != 0:
            return True

        name = dns.name.from_text(question_name + '.')
        answer = response.answer
        dns.dnssec.validate(answer[0], answer[1], {name: answer[0]})

    def handle_response(self, response):
        if not response:
            return None
        if self.cache:
            for answer in response.answer:
                self.cache.put(answer)
        return response.to_wire()

    def firewall_clearance(self, wire_message, client_ip):
        try:
            dns_message = dns.message.from_wire(wire_message)
            if client_ip in self.firewall['client_blacklist']:
                return False

            if self.firewall['rate_limit'] > -1:
                self.rate_per_second[0] += 1
                if int(time.time()) - self.rate_per_second[1] >= 1:
                    self.rate_per_second = [0, int(time.time())]
                if self.firewall['rate_limit'] <= self.rate_per_second[0]:
                    return False

            if self.firewall['refuse_ANY']:
                for q in dns_message.question:
                    if q.rdtype == dns.rdatatype.ANY:
                        return False

            if self.firewall['AAAA_disabled']:
                for q in dns_message.question:
                    if q.rdtype == dns.rdatatype.AAAA:
                        return False
            return True
        except Exception as exc:
            print("[Error]:", exc)

    def wire_resolve(self, wire_message):
        """Parse wire messages received by inbounds and forward them to corresponding outbounds.

        :param wire_message: DNS query message received by inbound.
        :return: DNS response to the query.
        """
        
        try:
            dns_message = dns.message.from_wire(wire_message)
            message_flags = dns.flags.to_text(dns_message.flags)

            # raise an exception since 'wire_resolve' method should only process dns queries
            if 'QR' in message_flags:
                raise TypeError("DNS Resolver should only receive queries")

            # retrieve cached rrset from cache
            question_rrset = dns_message.question[0]
            question_name = question_rrset.name.to_text().rstrip('.')
            if self.cache:
                cached_response_rrset, ttl = self.cache.get(question_rrset)
                if cached_response_rrset:
                    dns_response = dns.message.make_response(dns_message)
                    dns_response.answer.append(cached_response_rrset)
                    return dns_response.to_wire()

            # check hosts
            hosts_record = encrypted_dns.utils.parse_domain_rules(self.hosts, question_name)
            if hosts_record:
                dns_response = dns.message.make_response(dns_message)
                if encrypted_dns.utils.is_valid_ipv4_address(hosts_record):
                    hosts_rrset = dns.rrset.from_text(question_rrset.name, 300, dns.rdataclass.IN,
                                                      dns.rdatatype.A, hosts_record)
                else:
                    if not hosts_record.endswith('.'):
                        hosts_record += '.'

                    hosts_rrset = dns.rrset.from_text(question_rrset.name, 300, dns.rdataclass.IN,
                                                      dns.rdatatype.CNAME, hosts_record)
                dns_response.answer.append(hosts_rrset)
                return dns_response.to_wire()

            # add ecs to query message
            self.edns_subnet_client(dns_message, self.ecs_ip_address)

            # list of outbounds in config.json
            outbound_group, is_concurrent = OutboundHandler.get_group(question_name, self.domain_group, self.tag_group)
            proxy = outbound_group.get('proxies', None)
            if is_concurrent:
                executor = concurrent.futures.ThreadPoolExecutor(max_workers=10)
                result_pool = []
                for outbound in outbound_group['dns']:
                    result_pool.append(executor.submit(self._resolve_thread, outbound, dns_message, question_name, proxy))
                
                first = concurrent.futures.wait(result_pool, timeout=60, return_when=concurrent.futures.FIRST_COMPLETED)
                dns_response = next(iter(first[0])).result()
                executor.shutdown()
            else:
                outbound = OutboundHandler.random_outbound(outbound_group)
                dns_response = self._resolve_thread(outbound, dns_message, question_name, proxy)

            return self.handle_response(dns_response)

        except dns.message.ShortHeader:
            print('[Error]: The DNS packet passed to from_wire() is too short')
        except dns.message.TrailingJunk:
            print('[Error]:The DNS packet passed to from_wire() has extra junk at the end of it')
        except dns.message.UnknownHeaderField:
            print('[Error]: The header field name was not recognized when converting from text into a message')
        except dns.message.BadEDNS:
            print('[Error]: An OPT record occurred somewhere other than the start of the additional data section')
        except dns.message.UnknownTSIGKey:
            print('[Error]: A TSIG with an unknown key was received')
        except dns.message.BadTSIG:
            print('[Error]: A TSIG record occurred somewhere other than the end of the additional data section')
        except dns.name.BadLabelType:
            print('[Error]: The label type in DNS name wire format is unknown')
        except dns.exception.Timeout:
            print('[Error]: The DNS operation timed out')
        except Exception as exc:
            print('[Error]:', exc)

    def _resolve_thread(self, outbound, dns_message, question_name, proxy):
        try:
            protocol, dns_address, port = encrypted_dns.utils.parse_dns_address(outbound)
            is_valid_ip_address = encrypted_dns.utils.is_valid_ipv4_address(dns_address)

            if protocol in ('https', 'tls', 'doh', 'dot') and not is_valid_ip_address:
                if 'bootstrap' in self.tag_group:
                    bootstrap_dns_ip = self.tag_group['bootstrap']['dns'][0]
                else:
                    bootstrap_dns_ip = '1.0.0.1'

                ip_address = OutboundHandler.resolve_outbound_ip(dns_address, bootstrap_dns_ip, self.hosts)
                outbound = {
                    'protocol': protocol,
                    'domain': dns_address,
                    'ip': ip_address,
                    'port': port,
                    'proxy': proxy
                }
            else:
                outbound = {
                    'protocol': protocol,
                    'ip': dns_address,
                    'port': port
                }

            dns_response = self.protocol_methods[protocol].__call__(dns_message, outbound)
            if self.dnssec and not self.validate_dnssec(question_name, outbound, protocol):
                return None
            return dns_response
        except Exception:
            raise

    @staticmethod
    def _udp_resolve(dns_message, outbound):
        udp = encrypted_dns.outbound.DatagramOutbound.from_dict(outbound)
        return udp.query(dns_message)

    @staticmethod
    def _tcp_resolve(dns_message, outbound):
        tcp = encrypted_dns.outbound.StreamOutbound.from_dict(outbound)
        return tcp.query(dns_message)

    @staticmethod
    def _https_resolve(dns_message, outbound):
        https = encrypted_dns.outbound.HTTPSOutbound.from_dict(outbound)
        return https.query(dns_message)

    @staticmethod
    def _tls_resolve(dns_message, outbound):
        tls = encrypted_dns.outbound.TLSOutbound.from_dict(outbound)
        return tls.query(dns_message)
