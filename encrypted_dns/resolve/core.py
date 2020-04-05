import random

import encrypted_dns.outbound

import dns.message
import dns.flags


class OutboundHandler:
    @staticmethod
    def random_outbound(outbound_list, weighted=False):
        """
        Get a random outbound from the list of outbounds specified in config.json.
        :param outbound_list: List of outbounds.
        :param weighted: Whether to use weighted random selection.
        :return: Dictionary of outbound and type of outbound
        """
        populations, weights = [], []
        for outbound in outbound_list:
            if weighted:
                weights.append(outbound.get('weight', 0))
            else:
                weights.append(0)

        if weighted:
            result = random.choices(populations=populations, weights=weights, k=1)
        else:
            result = random.choice(populations)
        return result, result['protocol']

    @staticmethod
    def _resolve_outbound_ip(outbound_address, bootstrap_dns_address):
        """
        Resolve ip address of HTTPS or TLS outbound with bootstrap dns address.
        :param outbound_address: domain name of HTTPS or TLS outbound
        :param bootstrap_dns_address: dns server for resolving 'outbound_address'
        :return: ip address of HTTPS or TLS outbound
        """
        dns_query = dns.message.make_query(outbound_address, dns.rdatatype.A)
        response = dns.query.udp(dns_query, bootstrap_dns_address, port=53, timeout=0)
        for answer in response.answer:
            print(answer)
        return response.answer


class WireMessageHandler:
    def __init__(self):
        pass

    @staticmethod
    def wire_resolve(wire_message, outbound_list):
        """
        Parse wire messages received by inbounds and forward them to corresponding outbounds.
        :param wire_message: DNS query message received by inbound.
        :param outbound_list: List of outbounds specified in config.json.
        :return: DNS response to the query.
        """
        try:
            # create a dictionary that map protocol of outbound to the method for resolve
            protocol_methods = {
                'udp': WireMessageHandler._udp_resolve,
                'tcp': WireMessageHandler._tcp_resolve,
                'tls': WireMessageHandler._tcp_resolve,
                'dot': WireMessageHandler._tcp_resolve,
                'https': WireMessageHandler._https_resolve,
                'doh': WireMessageHandler._https_resolve,
            }

            dns_message = dns.message.from_wire(wire_message)
            message_flags = dns.flags.to_text(dns_message.flags)

            # raise an exception since 'wire_resolve' method should only proce dns queries
            if 'QR' not in message_flags:
                raise Exception()

            # list of outbounds in config.json
            outbound, protocol = OutboundHandler.random_outbound(outbound_list, weighted=True)
            return protocol_methods[protocol].__call__(dns_message, outbound)

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

    @staticmethod
    def _udp_resolve(dns_message, outbound):
        udp = encrypted_dns.outbound.DatagramOutbound.from_dict(outbound)
        return udp.query(dns_message)

    @staticmethod
    def _tcp_resolve(dns_message, outbound):
        tls = encrypted_dns.outbound.StreamOutbound.from_dict(outbound)
        return tls.query(dns_message)

    @staticmethod
    def _https_resolve(dns_message, outbound):
        https = encrypted_dns.outbound.HTTPSOutbound.from_dict(outbound)
        return https.query(dns_message)

    @staticmethod
    def _tls_resolve(dns_message, outbound):
        tls = encrypted_dns.outbound.TLSOutbound.from_dict(outbound)
        return tls.query(dns_message)
