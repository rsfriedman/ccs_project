import hashlib
class sPOW:
    chunk_size = 256
    def __init__(self, local_file_path):
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
        temp = len(temp)
        print(temp)
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

