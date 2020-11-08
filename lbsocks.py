from socketserver import StreamRequestHandler, ThreadingTCPServer
import selectors
import struct
import socket

# RFC 1928 reference: 
# https://www.ietf.org/rfc/rfc1928.txt


SOCKS_VERSION = 5
DEFAULT_PORT = 1080
FORMAT_SINGLE_OCTET = "!B"

class LBSocksServer(ThreadingTCPServer):
    pass


class SocksTCPHandler(StreamRequestHandler):
    def get_octects(self, buffer, num):
        """ convert bytes received from network to octets. octets are returned in a tuple. """
        FORMAT = "!" + "B" * num
        octets = struct.unpack(FORMAT, buffer)
        return octets


    def recv_all(self, length):
        buffer = b''
        bytes_recved = 0
        while bytes_recved < length:
            chunk = self.request.recv(min(512, length - bytes_recved))
            bytes_recved += len(chunk)
            buffer += chunk
        return buffer


    def recv_auth_negotiation(self):
        VER, NMETHODS = self.get_octects(self.request.recv(2), 2)
        assert VER == SOCKS_VERSION
        print(VER)
        print(NMETHODS)

        METHODS = self.recv_all(NMETHODS)

        # TODO with METHODS
    

    def reply_auth_negotiation(self):
        # SO FAR WE ONLY SUPPORT NO AUTH (^.^)
        FORMAT = "!BB"
        packet = struct.pack(FORMAT, SOCKS_VERSION, 0)
        self.request.sendall(packet)

    
    def recv_request_details(self):
        # SO FAR WE ONLY SUPPORT CONNECT REQUEST AND IPV4 ADDRESS (^.^)
        VER, CMD, RSV, ATYP = self.get_octects(self.request.recv(4), 4)
        
        assert VER == 5
        assert CMD == 1
        assert ATYP == 1

        DST_ADDR = socket.inet_ntoa(b''.join(self.get_octects(self.request.recv_all(32), 4)))
        DST_PORT = socket.ntohs(b''.join(self.get_octects(self.request.recv(2), 2)))

        return DST_ADDR, DST_PORT


    def reply_request_details(self):
        """
        docstring
        """
        pass


    def handle(self):
        """
        socks5 server workflow:

        NOTES:
            VER in the following messages are set to 5 as this is socks protocol version 5.
            All numbers in the following messages are in octets.

        1. client connects to socks5 server (conventionally port 1080)

        2. client sends a auth type negotiation message in the form: 

            +----+----------+----------+
            |VER | NMETHODS | METHODS  |
            +----+----------+----------+
            | 1  |    1     | 1 to 255 |
            +----+----------+----------+

        3. The server selects from one of the methods given in METHODS, and sends a METHOD selection message:

            +----+--------+
            |VER | METHOD |
            +----+--------+
            | 1  |   1    |
            +----+--------+

            If the selected METHOD is X'FF', none of the methods listed by the client are acceptable, and the client MUST close the connection.

            The values currently defined for METHOD are:

            X'00' NO AUTHENTICATION REQUIRED
            X'01' GSSAPI
            X'02' USERNAME/PASSWORD
            X'03' to X'7F' IANA ASSIGNED
            X'80' to X'FE' RESERVED FOR PRIVATE METHODS
            X'FF' NO ACCEPTABLE METHODS

        4. method-specific sub-negotiation

        5. client sends request details in the form:

            +----+-----+-------+------+----------+----------+
            |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            +----+-----+-------+------+----------+----------+
            | 1  |  1  | X'00' |  1   | Variable |    2     |
            +----+-----+-------+------+----------+----------+

            Where:
                o  VER  protocol version: X'05'
                o  CMD
                    o  CONNECT X'01'
                    o  BIND X'02'
                    o  UDP ASSOCIATE X'03'
                o  RSV    RESERVED
                o  ATYP   address type of following address
                    o  IP V4 address: X'01'
                    o  DOMAINNAME: X'03'
                    o  IP V6 address: X'04'
                o  DST.ADDR       desired destination address
                o  DST.PORT desired destination port in network octet
                    order

        6. server evaluates the request and returns a reply formed as follows:

            +----+-----+-------+------+----------+----------+
            |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
            +----+-----+-------+------+----------+----------+
            | 1  |  1  | X'00' |  1   | Variable |    2     |
            +----+-----+-------+------+----------+----------+

            Where:

                o  VER    protocol version: X'05'
                o  REP    Reply field:
                    o  X'00' succeeded
                    o  X'01' general SOCKS server failure
                    o  X'02' connection not allowed by ruleset
                    o  X'03' Network unreachable
                    o  X'04' Host unreachable
                    o  X'05' Connection refused
                    o  X'06' TTL expired
                    o  X'07' Command not supported
                    o  X'08' Address type not supported
                    o  X'09' to X'FF' unassigned
                o  RSV    RESERVED
                o  ATYP   address type of following address

        7. 
        """
        
        self.recv_auth_negotiation()
        self.reply_auth_negotiation()

        dst_addr = self.recv_request_details()
        
        remote_socket = socket.socket()
        remote_socket.connect(dst_addr)

        # address of local socket connected with remote host
        bind_addr = remote_socket.getsockname()




if __name__ == "__main__":
    addr = ("0.0.0.0", DEFAULT_PORT)
    with LBSocksServer(addr, SocksTCPHandler) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()