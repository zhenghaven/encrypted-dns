import dns.message
import dns.flags
import dns.resolver


class OutboundHandler:
    def __init__(self):
        pass

    @staticmethod
    def _resolve_outbound_ip(outbound_address, bootstrap_dns_address):
        """
        Resolve ip addresses of HTTPS and TLS outbounds with bootstrap dns address.
        :param outbound_address:
        :param bootstrap_dns_address:
        :return:
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
    def wire_resolve(wire_message, outbound):
        """
        Parse wire messages received by inbounds and forward them to corresponding outbounds.
        :param wire_message:
        :param outbound:
        :return:
        """
        try:
            dns_message = dns.message.from_wire(wire_message)
            message_flags = dns.flags.to_text(dns_message.flags)

            # raise an exception since 'wire_resolve' method should only proce dns queries
            if 'QR' not in message_flags:
                raise Exception()

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
    def _udp_resolve(dns_message):
        pass

    @staticmethod
    def _tcp_resolves(dns_message):
        pass

    @staticmethod
    def _https_resolve(dns_message):
        pass

    @staticmethod
    def _tls_resolve(dns_message):
        pass
