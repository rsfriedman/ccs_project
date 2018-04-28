import argparse
import socketserver
from pow_packets import *
from example_pow import *
from pow_merkle_tree import *
from spow_implementation import *

def pow_factory_method(pow_string, local_file_path):
    if pow_string == "merkletree":
        return pow_merkle_tree(local_file_path)
    elif pow_string == "spow":
        return spow_implementation(local_file_path, True)
    #elif pow_string == "bloomfilter":
        #return pow_bloomfilter_implementation(local_file_path)
    else:
        print("Error: Unknown POW factory string")
        return None

# Dictionary that contains all of the files we've gotten so far
serverFiles = dict()
pow_type = None

class ServerCommandHandler(socketserver.BaseRequestHandler):

    def handle(self):

        # Wait for an incoming packet.  This packet will dictate the
        #   action that's about to take place
        receivedPacket = receivePowPacket(self.request)

        if receivedPacket.packet_id == AssertFileClaimPacket.PacketId:
            # This indicates that the client wants to assert claim over a file,
            #   either a new file, or an existing one.  If it's a new file, then
            #   the client will also upload it as part of this sequence.

            print('Received acp packet')
            print(receivedPacket.file_name)
            print(receivedPacket.file_hash)

            # @todo This is just a temporary name for now
            local_file_path = 'server_' + receivedPacket.file_name

            assertClaimPacket = receivedPacket

            clientPassedChallenge = True
            haveFileAlready = receivedPacket.file_hash in serverFiles
            if haveFileAlready:
                # If we already have the file, then challenge the client to prove ownership
                currentFileDict = serverFiles[receivedPacket.file_hash]
                pow_object = currentFileDict['pow_object']

                if pow_type == 'spow':
                    if pow_object.num_challenges_computed - pow_object.num_challenges_used == 0:
                        pow_object.computeChallenges()
                    print("Server Bit Count: " + str(len(pow_object.challenges[pow_object.num_challenges_used])))
                    cfcp = ChallengeFileClaimRequest(assertClaimPacket.file_hash, None, pow_object.seeds[pow_object.num_challenges_used])
                    sendPowPacket(self.request, cfcp)

                    receivedPacket = receivePowPacket(self.request)
                    if receivedPacket.packet_id == ChallengeFileClaimResponse.PacketId:
                        if receivedPacket.bits == pow_object.challenges[pow_object.num_challenges_used]:
                            print("Challenge Accepted")
                            clientPassedChallenge = True
                        else:
                            print("Challenge Failed")
                            clientPassedChallenge = False
                        pow_object.num_challenges_used += 1
                    else:
                        print('Error: Expected challenge file claim response here')
                else:
                    # Send a challenge packet for each of the portions the POW scheme will challenge
                    for ii in range(1, pow_object.num_challenge_portions()):

                        # Request the file signature of portion 'ii' of the file
                        cfcp = ChallengeFileClaimRequest(assertClaimPacket.file_hash, ii, None)
                        sendPowPacket(self.request, cfcp)

                        receivedPacket = receivePowPacket(self.request)
                        if receivedPacket.packet_id == ChallengeFileClaimResponse.PacketId:

                            # Validate that the file portion signature supplied by the client is equal to
                            #   the file portion signature we have on record
                            if receivedPacket.file_portion_signature != pow_object.get_file_portion_pow_signature(ii):
                                print('Challenge failed')
                                clientPassedChallenge = False
                            else:
                                print('Challenge portion accepted')
                        else:
                            print('Error: Expected challenge file claim response here')

            # Inform the client that the challenge was accepted or rejected
            cfca = ChallengeFileClaimAccepted(receivedPacket.file_hash, clientPassedChallenge, not haveFileAlready)
            sendPowPacket(self.request, cfca)

            # If we don't have the file yet, then read it from the client
            if clientPassedChallenge and not haveFileAlready:
                print('Requesting file upload')
                receivedPacket = receivePowPacket(self.request)
                total_file_bytes = bytearray()
                while receivedPacket.packet_id != UploadFileComplete.PacketId:

                    total_file_bytes = total_file_bytes + receivedPacket.portion_bytes

                    # @todo check the hash before acknowledging receipt
                    ufpr = UploadFilePortionReceive(receivedPacket.file_hash, receivedPacket.file_portion_id, True)
                    sendPowPacket(self.request, ufpr)

                    receivedPacket = receivePowPacket(self.request)

                print('Receive complete')
                with open(local_file_path, "wb") as f:
                    bytes = f.write(total_file_bytes)

                pow_data = pow_factory_method(pow_type, local_file_path)

                serverFiles[assertClaimPacket.file_hash] = dict()
                # @todo Different clients may call the same file by a different name.  Need to manage that.
                serverFiles[assertClaimPacket.file_hash]['file_name'] = assertClaimPacket.file_name
                serverFiles[assertClaimPacket.file_hash]['pow_object'] = pow_data
            else:
                print('File upload not needed, already exists')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='POW client')
    parser.add_argument('-ip', '--ip', help='IP address for the server', required=True)
    parser.add_argument('-port', '--port', help='IP port for the server', required=True)
    parser.add_argument('-pow_type', '--pow_type', help='The type of POW to use',
                        choices=['merkletree', 'spow', 'bloomfilter'],
                        required=True)

    args = vars(parser.parse_args())

    port = int(args['port'])
    ip_address = args['ip']
    pow_type = args['pow_type']
    print(port)
    print(ip_address)
    print(pow_type)

    server = socketserver.TCPServer((ip_address, port), ServerCommandHandler)

    server.serve_forever()