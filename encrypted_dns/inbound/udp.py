import socketserver
import logging

import dns.message

wire_message_handler = []


class DatagramInbound:
    @staticmethod
    def setup(host, port):
        logger = logging.getLogger("encrypted_dns.DatagramInbound")
        logger.info("UDP Inbound starts listening on {}:{}".format(host, port))

    @staticmethod
    def serve(host, port, wire_message_handler_object):
        """
        :param wire_message_handler_object: Instance of encrypted_dns.resolve.WireMessageHandler.
        :param host: Host address of Datagram Inbound Server.
        :param port: Port of Datagram Inbound Server.
        :return: Object reference of Datagram Inbound Server.
        """
        logger = logging.getLogger("encrypted_dns.DatagramInbound")
        try:
            wire_message_handler.append(wire_message_handler_object)
            datagram_inbound = socketserver.ThreadingUDPServer((host, port), DatagramHandler)
            DatagramInbound.setup(host, port)
            datagram_inbound.serve_forever()
            return datagram_inbound
        except OSError as exc:
            logger.exception(exc)


class DatagramHandler(socketserver.BaseRequestHandler):
    def setup(self):
        self.logger = logging.getLogger("encrypted_dns.DatagramHandler")

    def handle(self):
        """
        Forward received DNS queries to 'encrypted_dns.resolve.core'
        to resolve through outbound protocols.
        Send the resolved DNS responses to clients.
        """

        wire_data = self.request[0]
        self.logger.debug("Receive inbound msg: " + str(wire_data) + ". From: udp://" + str(self.client_address[0]))

        try:
            dns_message = dns.message.from_wire(wire_data)

            if wire_message_handler[0].firewall_clearance(dns_message, self.client_address[0]):
                resolve_data = wire_message_handler[0].wire_resolve(dns_message)
                datagram_socket = self.request[1]
                if resolve_data:
                    datagram_socket.sendto(resolve_data, self.client_address)
        except dns.message.ShortHeader:
            self.logger.error('The DNS packet passed to from_wire() is too short')
        except dns.message.TrailingJunk:
            self.logger.error('The DNS packet passed to from_wire() has extra junk at the end of it')
        except dns.name.BadLabelType:
            self.logger.error('The label type in DNS name wire format is unknown')
        except Exception as exc:
            self.logger.exception(exc)

        return None
