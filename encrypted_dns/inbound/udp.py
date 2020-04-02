import socketserver


class DatagramInbound:
    def __init__(self):
        pass

    @staticmethod
    def serve(host, port):
        """
        :param host: Host address of Datagram Inbound Server.
        :param port: Port of Datagram Inbound Server.
        :return: Object reference of Datagram Inbound Server.
        """
        datagram_inbound = socketserver.UDPServer((host, port), DatagramHandler)
        datagram_inbound.serve_forever()
        return datagram_inbound


class DatagramHandler(socketserver.BaseRequestHandler):
    def handle(self):
        """
        Forward received DNS queries to 'encrypted_dns.resolve.core'
        to resolve through outbound protocols.
        Send the resolved DNS responses to clients.
        """
        wire_data = self.request[0].strip()
        response_address = self.client_address[0]
        resolve_data = None
        datagram_socket = self.request[1]
        datagram_socket.sendto(resolve_data, self.client_address)
