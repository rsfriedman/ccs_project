import hashlib
from BloomFilter import *
import math
import random

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

class bloomfilter_implementation:

    chunk_size = 256

    # Initializes the data structure for the given file
    def __init__(self, local_file_path):

        self.local_file_path = local_file_path
        self.file_portion_dictionary = dict()
        self.portion_hash_dictionary = dict()

        self.hash_count = 0
        self.byte_io_count = 0
        self.num_hashes_calculated = 0
        self.bloom = BloomFilter(self.chunk_size, .05)

        m = hashlib.sha256()
        with open(local_file_path, "rb") as f:

            file_portion_id = 1
            bytes = self.read_bytes_from_file(f, self.chunk_size)
            while bytes != b"":
                # Compute the hash of the bytes of each portion
                self.portion_hash_dictionary[file_portion_id] = self.compute_bytes_hash(bytes)
                # Set the portion bytes
                self.file_portion_dictionary[file_portion_id] = bytes

                # Update the whole file hash with the current bytes
                m.update(bytes)

                # Update the bloom filter with the hash
                self.bloom.add(self.portion_hash_dictionary[file_portion_id])

                file_portion_id = file_portion_id + 1
                bytes = f.read(self.chunk_size)

        self.whole_file_hash = m.digest()

    # Read bytes from a file,
    #   also maintain a count of how many
    #   bytes are read from the file.
    def read_bytes_from_file(self, file_object, num_bytes):

        bytes = file_object.read(num_bytes)

        self.byte_io_count = self.byte_io_count + len(bytes)

        return bytes

    # Return a hash of the given bytes,
    #   also maintain a count of how many hashes
    #   are computed.
    def compute_bytes_hash(self, bytes_to_hash):
        m = hashlib.sha256()
        m.update(bytes_to_hash)
        self.hash_count = self.hash_count + 1

        return m.digest()

    # Return the bytes for the requested portion of the file, whatever a "portion" means for this
    #   POW structure
    def get_file_portion_bytes(self, portion_id):
        return self.file_portion_dictionary[portion_id]

    # Return a hash of the bytes of the file portion
    def get_file_portion_hash(self, portion_id):

        m = hashlib.sha256()
        m.update(self.bloom.retrieve(portion_id).encode('utf-8'))

        return m.digest()

    def generate_random_challenges(self):

        return random.sample(range(0, self.get_num_portions()-1), self.num_random_challenges())

    # Get the total number of portions in the file
    def get_num_portions(self):
        return self.bloom.size

    def num_random_challenges(self):

        # Use this to set a constant number of challenges
        num_challenges = 10

        return num_challenges

    def validate_portions(self, receivedPacket, pow_bloom):
        for portion_id in receivedPacket.file_portion_ids:
            file_portion_hash = receivedPacket.portion_structure[portion_id]
            self.hash_count = self.hash_count + 1
            if not pow_bloom.check(file_portion_hash):
                return False
        return True

    # Reset the metrics
    def reset_metrics(self):
        self.hash_count = 0
        self.byte_io_count = 0
        self.partial_hash_tree_bandwith = 0
        self.num_hashes_calculated = 0

    def generate_bloom_response(self, file_portion_ids):
        bloom_dict = dict()
        for portion_id in file_portion_ids:
            file_portion_hash = self.get_file_portion_hash(self.file_portion_dictionary[portion_id])
            bloom_dict[portion_id] = file_portion_hash
            self.num_hashes_calculated = self.num_hashes_calculated + 1
        return bloom_dict

    # def count_hashes(self):
    #     self.partial_hash_tree_bandwith = 0
    #     return