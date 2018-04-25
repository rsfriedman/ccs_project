import hashlib
import os
import random
computeChallengeAmount = 5
computeResponseAmount = 5
server_master_key = "Locks Everything"

class spow_implementation:
    chunk_size = 256

    def __init__(self, local_file_path, server):
        self.file_pointer = local_file_path
        self.challenges = []
        self.num_challenges_computed = 0
        self.num_challenges_used = 0
        self.seeds = []
        self.file_portion_dictionary = dict()

        m = hashlib.sha256()
        with open(local_file_path, "rb") as f:
            file_portion_id = 1
            bytes = f.read(self.chunk_size)
            temp = bytes
            while bytes != b"":
                m.update(bytes)
                self.file_portion_dictionary[file_portion_id] = bytes
                file_portion_id = file_portion_id + 1
                bytes = f.read(self.chunk_size)
                temp = temp + bytes
        self.whole_file_hash = m.digest()
        if server:
            self.computeChallenges()

    def get_num_of_unused_challenges(self):
        return self.num_challenges_computed - self.num_challenges_used

    def get_file_portion_bytes(self, portion_id):
        return self.file_portion_dictionary[portion_id]

    def get_file_portion_pow_signature(self, portion_id):
        m = hashlib.sha256()
        m.update(self.file_portion_dictionary[portion_id])
        return m.digest()

    def get_file_portion_hash(self, portion_id):
        m = hashlib.sha256()
        m.update(self.file_portion_dictionary[portion_id])
        return m.digest()

    def get_num_portions(self):
        return len(self.file_portion_dictionary)

    def computeChallenges(self):
        filesize = os.path.getsize(self.file_pointer) * 8
        past_incrementer = self.num_challenges_used
        for x in range(0, computeChallengeAmount):
            ctr = self.num_challenges_computed + x
            temp_ctr = str(ctr)
            sha256 = hashlib.sha256()
            sha256.update(str.encode(temp_ctr))
            sha256.update(self.whole_file_hash)
            sha256.update(str.encode(server_master_key))
            s = sha256.digest()
            random.seed(s)
            self.seeds.append(s)
            self.challenges.append('')
            for y in range(0, computeResponseAmount):
                file_position = random.randrange(0, filesize)
                (q, r) = divmod(file_position, 8)
                with open(self.file_pointer, "rb") as f:
                    bit = (f.seek(q) >> r) & 1
                self.challenges[x + past_incrementer] = self.challenges[x + past_incrementer] + str(bit)
            print(self.challenges[x + past_incrementer])
            self.num_challenges_computed += 1

    def computeResponse(self, s):
        file_size = os.path.getsize(self.file_pointer) * 8
        random.seed(s)
        bits = ""
        for y in range(0, computeResponseAmount):
            file_position = random.randrange(0, file_size)
            (q, r) = divmod(file_position, 8)
            with open(self.file_pointer, 'rb') as f:
                bit = (f.seek(q) >> r) & 1
            bits = bits + str(bit)
        return bits

