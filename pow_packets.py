import pickle
import struct

# Base class for all packets
class BasePacket:

    def __init__(self, packet_id):

        self.packet_id = packet_id

    def marshal(self):

        return pickle.dumps(self)

# Packet that the client sends to indicate that it is
#   claiming ownership over a particular file
class AssertFileClaimPacket(BasePacket):

    PacketId = 1

    def __init__(self, file_name, file_hash):

        BasePacket.__init__(self, self.PacketId)

        self.file_name = file_name
        self.file_hash = file_hash

# Packet that the server sends to the client to
#   request that the client prove ownership of a file
#   by providing the POW signature of a portion of the
#   file.
class ChallengeFileClaimRequest(BasePacket):

    PacketId = 2

    def __init__(self, file_hash, file_portion_id, seed):

        BasePacket.__init__(self, self.PacketId)

        self.file_hash = file_hash
        self.file_portion_id = file_portion_id
        self.seed = seed

# Packet that the client responds with to prove
#   that it knows the POW signature of a portion
#   of a certain file.
class ChallengeFileClaimResponse(BasePacket):

    PacketId = 3

    def __init__(self, file_hash, file_portion_id, file_portion_signature, bits):

        BasePacket.__init__(self, self.PacketId)

        self.file_hash = file_hash
        self.file_portion_id = file_portion_id
        self.file_portion_signature = file_portion_signature
        self.bits = bits

# Packet sent by the server to notify that the client
#   that it is either accepting or rejecting its
#   claim over a file.
#  The server also uses this to request that the client
#   upload a file if the server doesn't already have
#   that file.
class ChallengeFileClaimAccepted(BasePacket):

    PacketId = 4

    def __init__(self, file_hash, claim_accepted, needs_upload):

        BasePacket.__init__(self, self.PacketId)

        self.file_hash = file_hash
        self.claim_accepted = claim_accepted
        self.file_needs_upload = needs_upload

# Packet that contains the actual bytes of a portion of a file.
#   this is used to transfer a file in either direction,
#   from the client to the server, or from the server to the client.
class UploadFilePortionRequest(BasePacket):

    PacketId = 5

    def __init__(self, file_hash, file_portion_id, portion_bytes_hash, portion_bytes):

        BasePacket.__init__(self, self.PacketId)

        self.file_hash = file_hash
        self.file_portion_id = file_portion_id
        self.portion_bytes_hash = portion_bytes_hash
        self.portion_bytes = portion_bytes

# Packet sent to ACK or NACK valid receipt of a portion of a file.
#   It is assumed that the sender will resend the portion if
#   receive_success is set to False.
class UploadFilePortionReceive(BasePacket):

    PacketId = 6

    def __init__(self, file_hash, file_portion_id, receive_success):

        BasePacket.__init__(self, self.PacketId)

        self.file_hash = file_hash
        self.file_portion_id = file_portion_id
        self.receive_success = receive_success

# Packet sent to signal that the entire file has been sent.
class UploadFileComplete(BasePacket):

    PacketId = 7

    def __init__(self, file_hash):

        BasePacket.__init__(self, self.PacketId)

        self.file_hash = file_hash

# Receives a specific length of bytes from a socket
def recv_by_length(sock, num_bytes):
    chunks = []
    bytes_recd = 0
    while bytes_recd < num_bytes:
        chunk = sock.recv(num_bytes - bytes_recd)
        if chunk == b'':
            raise RuntimeError("socket connection broken")
        chunks.append(chunk)
        bytes_recd = bytes_recd + len(chunk)
    return b''.join(chunks)

# Sends a packet as:
#   Packet ID
#   length of the information
#   information of the packet
def sendPowPacket(sock, packet):

    packet_bytes = packet.marshal()

    packet_id_bytes = struct.pack('!i', packet.packet_id)
    packet_length_bytes = struct.pack('!i', len(packet_bytes))

    sock.sendall(packet_id_bytes)
    sock.sendall(packet_length_bytes)
    sock.sendall(packet_bytes)

# Receives a packet that was sent by sendPowPacket
def receivePowPacket(sock):

    recv_buffer = recv_by_length(sock, 4)
    packet_id = struct.unpack('!i', recv_buffer[:4])[0]

    recv_buffer = recv_by_length(sock, 4)
    packet_length = struct.unpack('!i', recv_buffer[:4])[0]

    recv_buffer = recv_by_length(sock, packet_length)
    return pickle.loads(recv_buffer)
