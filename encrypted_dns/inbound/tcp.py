import socketserver
import logging

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
    def handle(self):
        """
        Forward received DNS queries to 'encrypted_dns.resolve.core'
        to resolve through outbound protocols.
        Send the resolved DNS responses to clients.
        """
        wire_data = self.request[0]
        if wire_message_handler[0].firewall_clearance(wire_data, self.client_address[0]):
            resolve_data = wire_message_handler[0].wire_resolve(wire_data)
            if resolve_data:
                self.request.sendall(resolve_data)
        return None
