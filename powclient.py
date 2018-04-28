import argparse
import socket
import time
from pow_packets import *
from spow_implementation import *
from pow_merkle_tree import *

def pow_factory_method(pow_string, local_file_path):
    if pow_string == "merkletree":
        return pow_merkle_tree(local_file_path)
    elif pow_string == "spow":
        return spow_implementation(local_file_path, False)
    #elif pow_string == "bloomfilter":
        #return pow_bloomfilter_implementation(local_file_path)
    else:
        print("Error: Unknown POW factory string")
        return None

if __name__ == "__main__":


    parser = argparse.ArgumentParser(description='POW client')
    parser.add_argument('-ip', '--ip', help='IP address for the server', required=True)
    parser.add_argument('-port', '--port', help='IP port for the server', required=True)
    parser.add_argument('-action', '--action', help='The command to perform', choices=['upload', 'download'], required=True)
    parser.add_argument('-pow_type', '--pow_type', help='The type of POW to use', choices=['merkletree', 'spow', 'bloomfilter'],
                        required=True)

    args = vars(parser.parse_args())

    port = int(args['port'])
    ip_address = args['ip']
    pow_type = args['pow_type']
    print(port)
    print(ip_address)
    print(pow_type)

    if pow_type == 'merkletree':
        mt = pow_merkle_tree('/Users/YoDex/PycharmProjects/FileReputation/flamingo.jpg')
        mt.get_file_portion_pow_signature(10)

    # Socket setup
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:

        sock.connect((ip_address, port))

        # File upload sequence
        if args['action'] == 'upload':

            # First, compute the POW data structure for the file
            test_pow = pow_factory_method(pow_type, '/Users/YoDex/PycharmProjects/FileReputation/flamingo.jpg')

            # Tell the server that you're asserting claim on a file
            afcp = AssertFileClaimPacket('flamingo.jpg', test_pow.whole_file_hash)
            sendPowPacket(sock, afcp)

            # Wait for the server's response.
            #
            #   If the server doesn't have a file with the given hash, it will
            #       immediately send a ChallengeFileClaimAccepted packet and request upload.
            #
            #   If the server does have a file with the given hash, it will
            #       issue ChallengeFileClaimRequest packets to request that the
            #       client prove ownership
            receivedPacket = receivePowPacket(sock)

            # Perform a sanity check that the server and the client
            #   are talking about the same file
            if receivedPacket.file_hash != afcp.file_hash:
                print('Error: mismatched file hashes sanity check')

            # Enter into the "challenge" loop, where the server will
            #   challenge the client to provide the correct file
            #   portion signatures
            while receivedPacket.packet_id == ChallengeFileClaimRequest.PacketId:

                if pow_type == "spow":
                    bits = test_pow.computeResponse(receivedPacket.seed)
                    print("Client Bit Count: " + str(len(bits)))
                    cfcr = ChallengeFileClaimResponse(test_pow.whole_file_hash, None, None, bits)
                else:
                    # Provide the signature for the portion of the file being challenged
                    response_signature = test_pow.get_file_portion_pow_signature(receivedPacket.file_portion_id)
                    cfcr = ChallengeFileClaimResponse(receivedPacket.file_hash, receivedPacket.file_portion_id, response_signature, None)

                sendPowPacket(sock, cfcr)

                # Get the next request from the server
                receivedPacket = receivePowPacket(sock)

            if receivedPacket.packet_id == ChallengeFileClaimAccepted.PacketId:

                # Check that the claim was accepted
                if receivedPacket.claim_accepted:
                    print('File claim accepted')

                    # If the server doesn't have a copy of this file, then upload it,
                    #   otherwise, we're done here
                    if receivedPacket.file_needs_upload:
                        print('Uploading packet')

                        ii = 1
                        while ii <= test_pow.get_num_portions():
                            ufpr = UploadFilePortionRequest(test_pow.whole_file_hash,
                                                            ii,
                                                            test_pow.get_file_portion_hash(ii),
                                                            test_pow.get_file_portion_bytes(ii))
                            sendPowPacket(sock, ufpr)

                            receivedPacket = receivePowPacket(sock)

                            if receivedPacket.packet_id == UploadFilePortionReceive.PacketId:
                                # Validate that the chunk was received correctly.  If it wasn't,
                                #   then we need to resend it, so don't increment ii
                                if receivedPacket.receive_success:
                                    ii = ii + 1
                            else:
                                print('Error: expected portion receive packet')

                        ufc = UploadFileComplete(test_pow.whole_file_hash)
                        sendPowPacket(sock, ufc)
                        print('File upload complete')

                    else:
                        print('Server already has the file, upload not needed')

                else:
                    print('File claim rejected, not the owner of the file')

            else:
                print('Error: expected claim accepted packet')

        elif args['action'] == 'download':

            print('Download action not currently supported')

    finally:
        sock.close()



