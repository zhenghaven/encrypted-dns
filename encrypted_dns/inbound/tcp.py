import socketserver
import logging

import dns.message

wire_message_handler = []


class StreamInbound:
    @staticmethod
    def setup(host, port):
        logger = logging.getLogger("encrypted_dns.StreamInbound")
        logger.info("TCP Inbound starts listening on {}:{}".format(host, port))

    @staticmethod
    def serve(host, port, wire_message_handler_object):
        """
        :param wire_message_handler_object: Instance of encrypted_dns.resolve.WireMessageHandler.
        :param host: Host address of Datagram Inbound Server.
        :param port: Port of Datagram Inbound Server.
        :return: Object reference of Datagram Inbound Server.
        """
        wire_message_handler.append(wire_message_handler_object)
        stream_inbound = socketserver.ThreadingTCPServer((host, port), StreamHandler)
        StreamInbound.setup(host, port)
        stream_inbound.serve_forever()
        return stream_inbound


class StreamHandler(socketserver.BaseRequestHandler):
    def setup(self):
        self.logger = logging.getLogger("encrypted_dns.StreamHandler")

    def handle(self):
        """
        Forward received DNS queries to 'encrypted_dns.resolve.core'
        to resolve through outbound protocols.
        Send the resolved DNS responses to clients.
        """
        wire_data = self.request[0]
        self.logger.debug("Receive inbound msg: " + str(wire_data) + ". From: tcp://" + str(self.client_address[0]))

        try:
            dns_message = dns.message.from_wire(wire_data)

            if wire_message_handler[0].firewall_clearance(dns_message, self.client_address[0]):
                resolve_data = wire_message_handler[0].wire_resolve(dns_message)
                if resolve_data:
                    self.request.sendall(resolve_data)
        except dns.message.ShortHeader:
            self.logger.error('The DNS packet passed to from_wire() is too short')
        except dns.message.TrailingJunk:
            self.logger.error('The DNS packet passed to from_wire() has extra junk at the end of it')
        except dns.name.BadLabelType:
            self.logger.error('The label type in DNS name wire format is unknown')
        except Exception as exc:
            self.logger.exception(exc)

        return None
