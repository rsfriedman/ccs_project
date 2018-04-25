import hashlib
from BloomFilter import *

# Example POW scheme showing the interface.
#
#   The following methods are required:
#       get_file_portion_bytes(self, portion_id)
#       get_file_portion_pow_signature(self, portion_id)
#       get_file_portion_hash(self, portion_id)
#       get_num_portions(self)
#       num_challenge_portions(self)
#
#   Also, the class must have a member variable "whole_file_hash" that
#   contains a hash for the entire file, so that it may be uniquely
#   identified in the protocol.
class example_bloom:

    chunk_size = 256

    # Initializes the data structure for the given file
    def __init__(self, local_file_path):

        self.local_file_path = local_file_path
        self.bloom = BloomFilter(20, .05)

        m = hashlib.sha256()
        with open(local_file_path, "rb") as f:

            file_portion_id = 1
            bytes = f.read(self.chunk_size)
            while bytes != b"":
                m.update(bytes)
                self.bloom.add(bytes)

                file_portion_id = file_portion_id + 1
                bytes = f.read(self.chunk_size)

        self.whole_file_hash = m.digest()

    # Return the bytes for the requested portion of the file, whatever a "portion" means for this
    #   POW structure
    def get_file_portion_bytes(self, portion_id):
        return self.bloom.check(portion_id)

    # Return the POW signature for the requested portion of the file
    def get_file_portion_pow_signature(self, portion_id):
        m = hashlib.sha256()
        m.update(self.bloom.retrieve(portion_id).encode('utf-8'))

        return m.digest()

    # Return a hash of the bytes of the file portion
    def get_file_portion_hash(self, portion_id):

        m = hashlib.sha256()
        m.update(self.bloom.retrieve(portion_id).encode('utf-8'))

        return m.digest()

    # Get the total number of portions in the file
    def get_num_portions(self):
        return self.bloom.size

    # Get the total number of portions to challenge before
    #   accepting that the user has proven ownership.
    def num_challenge_portions(self):
        num_portions = 10
        if num_portions > self.get_num_portions():
            num_portions = self.get_num_portions()
        return num_portions
