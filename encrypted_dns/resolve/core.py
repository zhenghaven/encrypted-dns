import random
import time

import encrypted_dns.outbound

import dns.message
import dns.flags
import dns.edns


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
    def random_outbound(outbound_list, weighted=False):
        """
        Get a random outbound from the list of outbounds specified in config.json.
        :param outbound_list: List of outbounds.
        :param weighted: Whether to use weighted random selection.
        :return: Dictionary of outbound and type of outbound
        """
        population, weights = [], []
        for outbound in outbound_list:
            population.append(outbound)
            if weighted:
                weights.append(outbound.get('weight', 0))
            else:
                weights.append(0)

        if weighted:
            result = random.choices(population=population, weights=weights, k=1)[0]
        else:
            result = random.choice(population)
        return result, result['protocol']

    @staticmethod
    def _resolve_outbound_ip(outbound_address, bootstrap_dns_address):
        """
        Resolve ip address of HTTPS or TLS outbound with bootstrap dns address.
        :param outbound_address: domain name of HTTPS or TLS outbound
        :param bootstrap_dns_address: dns server for resolving 'outbound_address'
        :return: RRSet Answer of HTTPS or TLS outbound
        """
        dns_query = dns.message.make_query(outbound_address, dns.rdatatype.A)
        response = dns.query.udp(dns_query, bootstrap_dns_address, port=53, timeout=0)
        return response.answer


class WireMessageHandler:
    def __init__(self, outbound_list, cache_object, enable_ecs, bootstrap_dns_ip):
        self.cache = cache_object
        self.outbound_list = outbound_list
        self.ecs_ip_address = enable_ecs
        self.bootstrap_dns_ip = bootstrap_dns_ip

    @staticmethod
    def edns_subnet_client(query_message, ip):
        """
        Add edns subnet client option to query messages.
        :param query_message: DNS query message for processing.
        :param ip: IP Address to add as an option.
        :return: Processed DNS query message.
        """
        # srclen is 24 for ipv4, 56 for ipv6
        query_message.edns = dns.edns.ECSOption(ip, srclen=24, scopelen=0)
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
            print(question_rrset.name)
            cached_response_rrset, ttl = self.cache.get(question_rrset)
            if cached_response_rrset:
                dns_response = dns.message.make_response(dns_message)
                dns_response.answer.append(cached_response_rrset)
                return dns_response.to_wire()

            # list of outbounds in config.json
            outbound, protocol = OutboundHandler.random_outbound(self.outbound_list, weighted=True)
            outbound['bootstrap_dns_ip'] = self.bootstrap_dns_ip
            dns_response = protocol_methods[protocol].__call__(dns_message, outbound)

            # process response and update cache
            return self.handle_response(dns_response)

        except dns.message.ShortHeader:
            print('[Error]: The DNS packet passed to from_wire() is too short.')
        except dns.message.TrailingJunk:
            print('[Error]:The DNS packet passed to from_wire() has extra junk at the end of it.')
        except dns.message.UnknownHeaderField:
            print('[Error]: The header field name was not recognized when converting from text into a message.')
        except dns.message.BadEDNS:
            print('[Error]: An OPT record occurred somewhere other than the start of the additional data section.')
        except dns.message.UnknownTSIGKey:
            print('[Error]: A TSIG with an unknown key was received.')
        except dns.message.BadTSIG:
            print('[Error]: A TSIG record occurred somewhere other than the end of the additional data section.')
        except dns.name.BadLabelType:
            print('[Error]: The label type in DNS name wire format is unknown.')
        except dns.exception.Timeout:
            print('[Error]: The DNS operation timed out.')

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
