import random
import time

import dns.edns
import dns.flags
import dns.message

import encrypted_dns.outbound


class CacheHandler:
    def __init__(self):
        self._cache = {}

    def get_cache_dict(self):
        return self._cache

    def get(self, rrset):
        if (rrset.name, rrset.rdtype, rrset.rdclass) in self._cache:
            (response_rrset, ttl, put_time) = self._cache[(rrset.name, rrset.rdtype, rrset.rdclass)]
            # purge cache if time exceeds ttl
            if int(time.time()) - put_time >= ttl:
                self._cache.pop((rrset.name, rrset.rdtype, rrset.rdclass))
                return None, None
            else:
                return response_rrset, ttl
        return None, None

    def put(self, rrset):
        self._cache[(rrset.name, rrset.rdtype, rrset.rdclass)] = (rrset, rrset.ttl, int(time.time()))

    def flush(self):
        self._cache = {}


class OutboundHandler:
    @staticmethod
    def get_group(query_name, outbounds, rules=None):
        return outbounds['encrypted'], outbounds['encrypted']['concurrent']

    @staticmethod
    def random_outbound(outbounds):
        """
        Get a random outbound from the list of outbounds specified in config.json.
        :param outbounds: List of outbounds.
        :return: Dictionary of outbound and type of outbound
        """
        population = []
        for outbound in outbounds:
            population.append(outbound)

        result = random.choice(population)
        return encrypted_dns.utils.parse_dns_address(result)

    @staticmethod
    def resolve_outbound_ip(outbound_address, bootstrap_dns_ip):
        """
        Resolve ip address of HTTPS or TLS outbound with bootstrap dns address.
        :param outbound_address: domain name of HTTPS or TLS outbound
        :param bootstrap_dns_ip: DNS server for resolving 'outbound_address'
        :return: RRSet Answer of HTTPS or TLS outbound
        """
        dns_query = dns.message.make_query(outbound_address, dns.rdatatype.A)
        response = dns.query.udp(dns_query, bootstrap_dns_ip, port=53, timeout=0)
        if len(response.answer) == 1:
            return response.answer[0].items[0]
        else:
            return response.answer[-1].items[0]


class WireMessageHandler:
    def __init__(self, outbounds, cache_object, ecs_ip_address):
        self.cache = cache_object
        self.outbounds = outbounds
        self.ecs_ip_address = ecs_ip_address
        self.bootstrap_dns_ip = '1.0.0.1'
        for group in outbounds:
            if group['tag'] == 'bootstrap':
                self.bootstrap_dns_ip = group['dns']

    @staticmethod
    def edns_subnet_client(query_message, ip):
        """
        Add edns subnet client option to query messages.
        :param query_message: DNS query message for processing.
        :param ip: IP Address to add as an option.
        :return: Processed DNS query message.
        """
        query_message.edns = dns.edns.ECSOption(ip)
        return query_message

    def handle_response(self, response):
        for answer in response.answer:
            self.cache.put(answer)
        return response.to_wire()

    def wire_resolve(self, wire_message):
        """
        Parse wire messages received by inbounds and forward them to corresponding outbounds.
        :param wire_message: DNS query message received by inbound.
        :return: DNS response to the query.
        """
        try:
            # create a dictionary that map protocol of outbound to the method for resolve
            protocol_methods = {
                'udp': WireMessageHandler._udp_resolve,
                'tcp': WireMessageHandler._tcp_resolve,
                'tls': WireMessageHandler._tls_resolve,
                'dot': WireMessageHandler._tls_resolve,
                'https': WireMessageHandler._https_resolve,
                'doh': WireMessageHandler._https_resolve,
            }

            dns_message = dns.message.from_wire(wire_message)
            message_flags = dns.flags.to_text(dns_message.flags)

            # raise an exception since 'wire_resolve' method should only process dns queries
            if 'QR' in message_flags:
                raise Exception()

            # retrieve cached rrset from cache
            question_rrset = dns_message.question[0]
            cached_response_rrset, ttl = self.cache.get(question_rrset)
            if cached_response_rrset:
                dns_response = dns.message.make_response(dns_message)
                dns_response.answer.append(cached_response_rrset)
                return dns_response.to_wire()

            # list of outbounds in config.json
            outbound_group, concurrent = OutboundHandler.get_group(question_rrset.name, self.outbounds)
            if concurrent:
                dns_response = None
            else:
                protocol, dns_address, port = OutboundHandler.random_outbound(outbound_group)
                is_valid_ip_address = encrypted_dns.utils.is_valid_ipv4_address(dns_address)

                if protocol in ('https', 'tls', 'doh', 'dot') and not is_valid_ip_address:
                    ip_address = OutboundHandler.resolve_outbound_ip(dns_address, self.bootstrap_dns_ip)
                    outbound = {
                        'protocol': protocol,
                        'domain': dns_address,
                        'ip': ip_address,
                        'port': port
                    }
                else:
                    outbound = {
                        'protocol': protocol,
                        'ip': dns_address,
                        'port': port
                    }

                dns_response = protocol_methods[protocol].__call__(dns_message, outbound)

            # process response and update cache
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
