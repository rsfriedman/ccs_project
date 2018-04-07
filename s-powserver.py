import argparse
import socketserver
from pow_packets import *
from sPOW import *
import hashlib
import binascii
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
            local_file_path = 'server_' + receivedPacket.file_name

            clientPassedChallenge = True
            haveFileAlready = receivedPacket.file_hash in serverFiles
            if haveFileAlready == False:
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
                    data = f.write(total_file_bytes)

                sha256 = hashlib.sha256()
                sha256.update(data)
                server_sPOW_file_hash = sha256.hexidigest()
                server_sPOW = sPOW(local_file_path)
                f.close()
                serverFiles[server_sPOW_file_hash] = server_sPOW
                computeChallenges(server_sPOW_file_hash)

                file_verify = serverFiles[server_sPOW_file_hash]
                sPOW_cfcp = sPOW_ChallengeFileClaimRequest(server_sPOW_file_hash, file_verify.seeds[0])
                sendPowPacket(self.request, sPOW_cfcp)

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
                server_sPOW_file_hash[server_sPOW_file_hash] = file_verify

                cfca = ChallengeFileClaimAccepted(receivedPacket.file_hash, clientPassedChallenge, False)
                sendPowPacket(self.request, cfca)

            if haveFileAlready == True:
                print("File Verificaiton Needed")
                file_verify = serverFiles[receivedPacket.file_hash]
                sPOW_cfcp = sPOW_ChallengeFileClaimRequest(receivedPacket.file_hash, file_verify.seeds[0])
                sendPowPacket(self.request, sPOW_cfcp)

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

                cfca = ChallengeFileClaimAccepted(receivedPacket.file_hash, clientPassedChallenge, False)
                sendPowPacket(self.request, cfca)

def computeChallenges(file_hash):
    sPOW = serverFiles[file_hash]
    with open(sPOW.file_pointer, "rb") as f:
        data = f.read()
        filesize = len(data) * 8
        for x in computeChallengeAmount - 1:
            ctr = sPOW.num_challenges_computed + x
            sha256 = hashlib.sha256
            sha256.update(ctr)
            sha256.update(file_hash)
            # todo add server master key once I know what that is
            s = sha256.hexidigest()
            random.seed(s)
            sPOW.seeds[x] = s
            for y in computeResponseAmount - 1:
                file_position = random.randrange(0, filesize)
                (q, r) = divmod(file_position, 8)
                bit = (data[q] >> r) & 1
                sPOW.challenges[x] = sPOW.challenges[x] + str(bit)
            sPOW.num_challenges_computed = ctr + 1
        f.close()
    serverFiles[file_hash] = sPOW

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
