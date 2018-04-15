import argparse
import socketserver
from pow_packets import *
from sPOW import *
import hashlib
import random

# Dictionary that contains all of the files we've gotten so far
serverFiles = dict()
computeChallengeAmount = 5
computeResponseAmount = 5

class ServerCommandHandler(socketserver.BaseRequestHandler):

    def handle(self):

        # Wait for an incoming packet.  This packet will dictate the
        #   action that's about to take place
        receivedPacket = receivePowPacket(self.request)

        if receivedPacket.packet_id == AssertFileClaimPacket.PacketId:
            # This indicates that the client wants to assert claim over a file,
            #   either a new file, or an existing one.  If it's a new file, then
            #   the client will also upload it as part of this sequence.

            print('Received Assert File Claim Packet')
            print(receivedPacket.file_name)
            print(receivedPacket.file_hash)
            server_file_path = 'server_' + receivedPacket.file_name

            clientPassedChallenge = True
            haveFileAlready = receivedPacket.file_hash in serverFiles
            if haveFileAlready == False:

                #File Upload Code
                print('Requesting file upload')
                cfca = ChallengeFileClaimAccepted(receivedPacket.file_hash, clientPassedChallenge, not haveFileAlready)
                sendPowPacket(self.request, cfca)
                receivedPacket = receivePowPacket(self.request)
                total_file_bytes = bytearray()
                while receivedPacket.packet_id != UploadFileComplete.PacketId:
                    total_file_bytes = total_file_bytes + receivedPacket.portion_bytes
                    # @todo check the hash before acknowledging receipt
                    ufpr = UploadFilePortionReceive(receivedPacket.file_hash, receivedPacket.file_portion_id, True)
                    sendPowPacket(self.request, ufpr)
                    receivedPacket = receivePowPacket(self.request)
                print('Receive complete')

                #Creating sPOW object, storing object in serverFiles, computing challenges new sPOW object
                with open(server_file_path, "wb") as f:
                    f.write(total_file_bytes)
                f.close()
                m = hashlib.sha256()
                print(str(len(total_file_bytes)))
                m.update(total_file_bytes)
                server_sPOW_file_hash = m.digest()
                server_sPOW = sPOW(server_file_path)

                serverFiles[server_sPOW_file_hash] = server_sPOW
                print("Need to compute challenges.")
                computeChallenges(server_sPOW_file_hash)

                #Challenge Client for proof of ownership
                print("Verifying client owns the file upload...")
                file_verify = serverFiles[server_sPOW_file_hash]
                sPOW_cfcp = sPOW_ChallengeFileClaimRequest(server_sPOW_file_hash, file_verify.seeds[0])
                sendPowPacket(self.request, sPOW_cfcp)

                #Verify client's challenge response
                receivedPacket = receivePowPacket(self.request)
                if receivedPacket.packet_id == sPOW_ChallengeFileClaimResponse.PacketId:
                    if receivedPacket.bits == file_verify.challenges[0]:
                        print("Challenge Accepted")
                        clientPassedChallenge = True
                    else:
                        print("Challenge Failed")
                        clientPassedChallenge = False
                    file_verify.num_challenges_used += 1
                else:
                    print('Error: Expected challenge file claim response here')

                serverFiles[server_sPOW_file_hash] = file_verify

                #sending client the status of their claim
                cfca = ChallengeFileClaimAccepted(receivedPacket.file_hash, clientPassedChallenge, False)
                sendPowPacket(self.request, cfca)

            # Challenge Client for file proof of ownership
            if haveFileAlready == True:
                print("File Verificaiton Needed")

                #checking if there are anymore challenges left, if not create more
                file_verify = serverFiles[receivedPacket.file_hash]
                if file_verify.get_num_of_unused_challenges == 0:
                    computeChallenges(receivedPacket.file_hash)
                    file_verify = serverFiles[receivedPacket.file_hash]

                #sending challenge to client
                sPOW_cfcp = sPOW_ChallengeFileClaimRequest(receivedPacket.file_hash, file_verify.seeds[file_verify.num_challenges_used])
                sendPowPacket(self.request, sPOW_cfcp)

                #verify client's challenge resposne
                receivedPacket = receivePowPacket(self.request)
                if receivedPacket.packet_id == sPOW_ChallengeFileClaimResponse.PacketId:
                    if receivedPacket.bits == file_verify.challenges[0]:
                        print("Challenge Accepted")
                        clientPassedChallenge = True
                    else:
                        print("Challenge Failed")
                        clientPassedChallenge = False
                    file_verify.num_challenges_used += 1
                else:
                    print('Error: Expected challenge file claim response here')
                serverFiles[receivedPacket.file_hash] = file_verify

                #sending client the status of their claim
                cfca = ChallengeFileClaimAccepted(receivedPacket.file_hash, clientPassedChallenge, False)
                sendPowPacket(self.request, cfca)

#computing challenges
def computeChallenges(file_hash):
    sPOW = serverFiles[file_hash]
    with open(sPOW.file_pointer, "rb") as f:
        data = f.read()
    f.close()
    filesize = len(data) * 8
    #print('filesize: ' + str(filesize))
    for x in range(0,computeChallengeAmount - 1):
        ctr = sPOW.num_challenges_computed + x
        temp_ctr = str(ctr)
        sha256 = hashlib.sha256()
        sha256.update(str.encode(temp_ctr))
        sha256.update(file_hash)
        # todo add server master key to seed once I know what that is
        s = sha256.digest()
        random.seed(s)
        sPOW.seeds.append(s)
        sPOW.challenges.append('')
        for y in range(0,computeResponseAmount - 1):
            file_position = random.randrange(0, filesize)
            (q, r) = divmod(file_position, 8)
            bit = (data[q] >> r) & 1
            sPOW.challenges[x] = sPOW.challenges[x] + str(bit)
        print(sPOW.challenges[x])
        sPOW.num_challenges_computed = ctr + 1

    serverFiles[file_hash] = sPOW
    print("Computing challenges finished")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='POW client')
    parser.add_argument('-ip', '--ip', help='IP address for the server', required=True)
    parser.add_argument('-port', '--port', help='IP port for the server', required=True)

    args = vars(parser.parse_args())

    port = int(args['port'])
    ip_address = args['ip']
    print(port)
    print(ip_address)

    server = socketserver.TCPServer((ip_address, port), ServerCommandHandler)

    server.serve_forever()
