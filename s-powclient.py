import argparse
import socket
import random
from pow_packets import *
from sPOW import *

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='POW client')
    parser.add_argument('-ip', '--ip', help='IP address for the server', required=True)
    parser.add_argument('-port', '--port', help='IP port for the server', required=True)
    parser.add_argument('-action', '--action', help='The command to perform', choices=['upload', 'download'], required=True)

    args = vars(parser.parse_args())

    port = int(args['port'])
    ip_address = args['ip']
    print(port)
    print(ip_address)

    # Socket setup
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:

        sock.connect((ip_address, port))

        # File upload sequence
        if args['action'] == 'upload':

            # First, compute the sPOW data structure for the file
            sPOW = sPOW('/Users/YoDex/PycharmProjects/ccs_project/flamingo.jpg')

            # Tell the server that you're asserting claim on a file
            afcp = AssertFileClaimPacket('flamingo.jpg', sPOW.whole_file_hash)
            sendPowPacket(sock, afcp)

            receivedPacket = receivePowPacket(sock)
            if receivedPacket.file_needs_upload:
                print('Uploading packet')

                ii = 1
                while ii <= sPOW.get_num_portions():
                    ufpr = UploadFilePortionRequest(sPOW.whole_file_hash,
                                                    ii,
                                                    sPOW.get_file_portion_hash(ii),
                                                    sPOW.get_file_portion_bytes(ii))
                    sendPowPacket(sock, ufpr)

                    receivedPacket = receivePowPacket(sock)

                    if receivedPacket.packet_id == UploadFilePortionReceive.PacketId:
                        # Validate that the chunk was received correctly.  If it wasn't,
                        #   then we need to resend it, so don't increment ii
                        if receivedPacket.receive_success:
                            ii = ii + 1
                    else:
                        print('Error: expected portion receive packet')

                ufc = UploadFileComplete(sPOW.whole_file_hash)
                sendPowPacket(sock, ufc)
                print('File upload complete')

                receivedPacket = receivePowPacket(sock)
                print("Verifying file ownership to server.")
                with open(sPOW.file_pointer, 'rb') as f:
                    data = f.read()
                f.close()
                file_size = len(data)
                print('filesize: ' + str(file_size))
                random.seed(receivedPacket.seed)
                bits = ""
                for y in range(0, 4):
                    file_position = random.randrange(0, file_size)
                    (q, r) = divmod(file_position, 8)
                    bit = (data[q] >> r) & 1
                    bits = bits + str(bit)
                print(receivedPacket.seed)
                print(bits)
                print("Sending challenge resposne to server.")
                spow_cfcr = sPOW_ChallengeFileClaimResponse(sPOW.whole_file_hash, bits)
                sendPowPacket(sock, spow_cfcr)

                receivedPacket = receivePowPacket(sock)

                if receivedPacket.packet_id == ChallengeFileClaimAccepted.PacketId:
                    if receivedPacket.claim_accepted == True:
                        print("File owernship proven!")
                    else:
                        print("File ownership challenge failed")

            if receivedPacket.packet_id == sPOW_ChallengeFileClaimRequest.PacketId:
                print("Server already has file, but needs to verify ownership")
                print("Verifying file ownership to server.")
                with open(sPOW.file_pointer, 'rb') as f:
                    data = f.read()
                f.close()
                file_size = len(data)
                print('filesize: ' + str(file_size))
                random.seed(receivedPacket.seed)
                bits = ""
                for y in range(0, 4):
                    file_position = random.randrange(0, file_size)
                    (q, r) = divmod(file_position, 8)
                    bit = (data[q] >> r) & 1
                    bits = bits + str(bit)
                print("Sending challenge resposne to server.")
                spow_cfcr = sPOW_ChallengeFileClaimResponse(sPOW.whole_file_hash, bits)
                sendPowPacket(sock, spow_cfcr)

                receivedPacket = receivedPacket(sock)

                if receivedPacket.packet_id == ChallengeFileClaimAccepted.PacketId:
                    print("File owernship proven!")
                else:
                    print("File ownership challenge failed")
    finally:
        sock.close()

def challenge_response(seed, file):
    file_size = len(data)
    random.seed(seed)
    bits = ""
    for y in range(0, 4):
        file_position = random.randrange(0, file_size)
        (q, r) = divmod(file_position, 8)
        bit = (file[q] >> r) & 1
        bits = bits + str(bit)
    return bits
