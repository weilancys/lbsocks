from socketserver import StreamRequestHandler, ThreadingTCPServer
import selectors
import struct
import socket
import logging
import sys

# RFC 1928 reference: 
# https://www.ietf.org/rfc/rfc1928.txt


SOCKS_VERSION = 5
DEFAULT_PORT = 1080

# logger config
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(message)s")


class LBSocksServer(ThreadingTCPServer):
    pass


class SocksTCPHandler(StreamRequestHandler):
    def get_octets(self, buffer, num):
        """ convert bytes received from network to octets. octets are returned in a tuple. """
        FORMAT = "!" + "B" * num
        octets = struct.unpack(FORMAT, buffer)
        return octets


    def recvall(self, length):
        """ helper method for recving long data from a stream socket """
        buffer = b''
        bytes_recved = 0
        while bytes_recved < length:
            try:
                chunk = self.request.recv(min(512, length - bytes_recved))
                if not chunk:
                    raise ConnectionResetError("connection reset by peer")
                bytes_recved += len(chunk)
                buffer += chunk
            except Exception as e:
                self.server.shutdown_request(self.request)
                logging.exception(e)
                break
        return buffer


    def recv_auth_negotiation(self):
        VER, NMETHODS = struct.unpack("!BB", self.recvall(2))
        if VER != SOCKS_VERSION:
            self.server.shutdown_request(self.request)
        METHODS = self.recvall(NMETHODS)
        client_methods = struct.unpack("!" + NMETHODS * "B", METHODS)

        # TODO auth here


    def reply_auth_negotiation(self):
        # auth modes
        NO_AUTH = 0x00
        GSSAPI = 0x01
        USERNAME_PASSWORD = 0x02
        NO_ACCEPTABLE_METHODS = 0xFF

        packet = struct.pack("!BB", SOCKS_VERSION, NO_AUTH) # only no auth supported so far
        try:
            self.request.sendall(packet)
        except Exception as e:
            logging.exception(e)
            self.server.shutdown_request(self.request)
        

    def recv_request_details(self):
        VER, CMD, RSV, ATYP = struct.unpack("!BBBB", self.recvall(4))
        
        if VER != SOCKS_VERSION:
            self.server.shutdown_request(self.request)

        if CMD != 0x01:
            raise NotImplementedError # only connect cmd supported so far

        if ATYP == 0x01:
            # ipv4 ip address
            DST_ADDR = socket.inet_ntoa(self.request.recv(4))
            DST_PORT = struct.unpack("!H", self.request.recv(2))[0]
        elif ATYP == 0x03:
            # domain name
            addr_length = struct.unpack("!B", self.request.recv(1))
            domain_name = "".join(struct.unpack("!" + "c"*addr_length, self.request.recv(addr_length)))
            DST_ADDR = socket.gethostbyname(domain_name)
            DST_PORT = struct.unpack("!H", self.request.recv(2))[0]
        elif ATYP == 0x04:
            # ipv6 ip address
            raise NotImplementedError

        return DST_ADDR, DST_PORT


    def reply_request_details(self, bind_addr):
        FORMAT = "!BBBB4sH"

        VER = SOCKS_VERSION
        REP = 0
        RSV = 0
        ATYP = 1 # ipv4 only for now
        BND_ADDR = socket.inet_aton(bind_addr[0])
        BND_PORT = bind_addr[1]

        packet = struct.pack(FORMAT, VER, REP, RSV, ATYP, BND_ADDR, BND_PORT)

        try:
            self.request.sendall(packet)
        except Exception as e:
            logging.exception(e)
            self.server.shutdown_request(self.request)


    def reply_request_failure(self):
        VER = SOCKS_VERSION
        REP = 1 # general socks server failure
        RSV = 0
        ATYP = 1 # ipv4 only for now
        BND_ADDR = 0
        BND_PORT = 0

        FORMAT = "!BBBBIH"
        packet = struct.pack(FORMAT, VER, REP, RSV, ATYP, BND_ADDR, BND_PORT)
        try:
            self.request.sendall(packet)
        except Exception as e:
            logging.exception(e)
            self.server.shutdown_request(self.request)



    def handle(self):
        """
        socks5 server workflow:

        NOTES:
            1. VER in the following messages are set to 5 as this is socks protocol version 5.
            2. All numbers in the following message diagrams represent the number of octets.

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
            o  DST.PORT desired destination port in network octet order

        6. server evaluates the request and returns a reply formed as follows:

            +----+-----+-------+------+----------+----------+
            |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
            +----+-----+-------+------+----------+----------+
            | 1  |  1  | X'00' |  1   | Variable |    2     |
            +----+-----+-------+------+----------+----------+

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

        7. commnication
        """
        
        self.recv_auth_negotiation()
        self.reply_auth_negotiation()

        dst_addr = self.recv_request_details()
        
        try:
            remote_socket = socket.socket()
            remote_socket.connect(dst_addr)
        except Exception as e:
            logging.exception(e)
            self.reply_request_failure()
            self.server.shutdown_request(self.request)

        bind_addr = remote_socket.getsockname()
        self.reply_request_details(bind_addr)

        selector = selectors.DefaultSelector()
        selector.register(remote_socket, selectors.EVENT_READ, None)
        selector.register(self.connection, selectors.EVENT_READ, None)

        selecting = True
        while selecting:
            events = selector.select()
            for key, event in events:
                sock = key.fileobj
                try:
                    if sock is remote_socket:
                        chunk = sock.recv(4096)
                        if not chunk:
                            raise ConnectionResetError("connection reset by peer")
                        self.connection.sendall(chunk)
                        logging.info(f"sending {len(chunk)} bytes to client {self.client_address[0]}:{self.client_address[1]}")
                    elif sock is self.connection:
                        chunk = sock.recv(4096)
                        if not chunk:
                            raise ConnectionResetError("connection reset by peer")
                        remote_socket.sendall(chunk)
                        logging.info(f"sending {len(chunk)} bytes to remote server {dst_addr[0]}:{dst_addr[1]}")
                except Exception as e:
                    logging.exception(e)
                    selecting = False
                    break
                        
        selector.close()
        remote_socket.close()
        self.server.shutdown_request(self.request)


if __name__ == "__main__":
    addr = ("0.0.0.0", DEFAULT_PORT + 1)
    with LBSocksServer(addr, SocksTCPHandler) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()