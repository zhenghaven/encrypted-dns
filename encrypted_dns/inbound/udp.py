import socketserver
import threading

wire_message_handler = None


class DatagramInbound:
    @staticmethod
    def setup(host, port):
        print("Datagram Inbound starts listening on {}:{}".format(host, port))

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
        DatagramInbound.setup(host, port)
        datagram_inbound.serve_forever()
        return datagram_inbound


class DatagramHandler(socketserver.BaseRequestHandler):

    def handle(self):
        """
        Forward received DNS queries to 'encrypted_dns.resolve.core'
        to resolve through outbound protocols.
        Send the resolved DNS responses to clients.
        """
        global wire_message_handler
        wire_data = self.request[0].strip()
        threading.Thread(target=self._thread, args=(wire_data,), daemon=True).start()

    def _thread(self, wire_data):
        resolve_data = wire_message_handler.wire_resolve(wire_data)
        datagram_socket = self.request[1]
        if resolve_data:
            datagram_socket.sendto(resolve_data, self.client_address)
