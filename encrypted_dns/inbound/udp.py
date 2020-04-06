import socketserver

wire_message_handler = None


class DatagramInbound:

    @staticmethod
    def serve(host, port, wire_message_handler_object):
        """
        :param wire_message_handler_object: Instance of encrypted_dns.resolve.WireMessageHandler.
        :param host: Host address of Datagram Inbound Server.
        :param port: Port of Datagram Inbound Server.
        :return: Object reference of Datagram Inbound Server.
        """
        global wire_message_handler
        wire_message_handler = wire_message_handler_object

        datagram_inbound = socketserver.UDPServer((host, port), DatagramHandler)
        datagram_inbound.serve_forever()
        return datagram_inbound


class DatagramHandler(socketserver.BaseRequestHandler):

    def setup(self):
        pass

    def handle(self):
        """
        Forward received DNS queries to 'encrypted_dns.resolve.core'
        to resolve through outbound protocols.
        Send the resolved DNS responses to clients.
        """
        global wire_message_handler
        wire_data = self.request[0].strip()
        resolve_data = wire_message_handler.wire_resolve(wire_data)
        datagram_socket = self.request[1]
        datagram_socket.sendto(resolve_data, self.client_address)
