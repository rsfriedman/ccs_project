import hashlib
import math
import random
import copy
from collections import OrderedDict

class merkle_node:

    def __init__(self, portion_id):

        self.hash = None
        self.children = OrderedDict()
        self.parent = None
        self.portion_id = portion_id

    def addChild(self, childNode):

        self.children[childNode.hash] = childNode
        childNode.parent = self

        self.computeSelfHash()

    def computeSelfHash(self):

        if self.hasChildren():
            m = hashlib.sha256()

            for childIndex in self.children:
                child = self.children[childIndex]

                m.update(child.hash)

            self.hash = m.digest()

    def hasChildren(self):
        return len(self.children) != 0

    def setHash(self, hash):
        self.hash = hash

    def numChildren(self):
        return len(self.children)

# Implementation of the POW scheme (Merkle tree) from the
# paper.
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
class pow_merkle_tree:

    chunk_size = 256
    node_challenge_factor = .2

    # Initializes the data structure for the given file
    def __init__(self, local_file_path):

        self.local_file_path = local_file_path
        self.file_portion_dictionary = dict()
        self.portion_hash_dictionary = dict()
        self.portion_node_dictionary = dict()
        self.node_list = list()

        self.hash_count = 0
        self.byte_io_count = 0
        self.partial_hash_tree_bandwith = 0
        self.num_hashes_calculated = 0

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

                # Update the list of file portion nodes
                portion_node = merkle_node(file_portion_id)
                portion_node.hash = self.portion_hash_dictionary[file_portion_id]
                self.node_list.append(portion_node)
                self.portion_node_dictionary[file_portion_id] = portion_node

                # Increment for the next portion and read the next chunk
                file_portion_id = file_portion_id + 1
                bytes = self.read_bytes_from_file(f, self.chunk_size)

        self.whole_file_hash = m.digest()

        #print('Num portions: %i'%(len(self.portion_node_dictionary)))

        total_num_nodes = 1
        latest_node_list = copy.deepcopy(self.node_list)
        while len(latest_node_list) != 1:
            total_num_nodes = total_num_nodes + len(latest_node_list)
            latest_node_list = self.make_tree_level(latest_node_list)

        #print('Total nodes in tree: %i'%(total_num_nodes))

        self.root_node = latest_node_list[0]

    # Return the bytes for the requested portion of the file, whatever a "portion" means for this
    #   POW structure
    def get_file_portion_bytes(self, portion_id):
        return self.file_portion_dictionary[portion_id]

    # Return the POW signature for the requested portion of the file
    def get_file_portion_pow_signature(self, portion_id):

        cur_node = self.portion_node_dictionary[portion_id]
        portion_signature = cur_node.hash
        cur_node = cur_node.parent

        while cur_node is not None:
            portion_signature += cur_node.hash
            cur_node = cur_node.parent

        return portion_signature

    # Return a hash of the bytes of the file portion
    def get_file_portion_hash(self, portion_id):

        m = hashlib.sha256()
        m.update(self.file_portion_dictionary[portion_id])

        return m.digest()

    # Get the total number of portions in the file
    def get_num_portions(self):
        return len(self.file_portion_dictionary)

    # Get the total number of portions to challenge before
    #   accepting that the user has proven ownership.
    def num_challenge_portions(self):

        # This code limits the number of challenge
        #   portions to some constant number
        #num_portions = 10
        #if num_portions > self.get_num_portions():
        #    num_portions = self.get_num_portions()

        # Use all of the challenge portions
        #num_portions = self.get_num_portions()

        # With the Bulk challenge packet, this is only 1
        num_portions = 1

        return num_portions

    def num_random_challenges(self):

        # Use this to set a certain percentage of challenges
        #num_challenges = math.ceil(self.get_num_portions() * self.node_challenge_factor)

        # Use this to set a constant number of challenges
        num_challenges = 1

        return num_challenges

    def generate_random_challenges(self):

        return random.sample(range(0, self.get_num_portions()-1), self.num_random_challenges())

    def generate_response_tree(self, random_leaf_numbers):

        latest_node_list = copy.deepcopy(self.node_list)
        while len(latest_node_list) != 1:
            latest_node_list = self.make_tree_level(latest_node_list)

        self.recurse_remove_nonsibling_hashes(latest_node_list[0], random_leaf_numbers)

        self.num_hashes_calculated = self.count_nonzero_hashes_recurse(latest_node_list[0]) - len(random_leaf_numbers) + len(self.portion_hash_dictionary)

        return latest_node_list[0]

    def recurse_remove_nonsibling_hashes(self, current_node, random_leaf_numbers):

        if current_node.hasChildren():
            num_child_node_hashes = 0
            for ii in current_node.children:
                self.recurse_remove_nonsibling_hashes(current_node.children[ii], random_leaf_numbers)
                if current_node.children[ii].hash is not None:
                    num_child_node_hashes = num_child_node_hashes + 1

            if current_node.hash is not None and num_child_node_hashes == len(current_node.children):
                for ii in current_node.children:
                    current_node.children[ii].hash = None
            else:
                current_node.hash = None

        else:
            if current_node.portion_id in random_leaf_numbers:
                current_node.parent.hash = None

    def validate_portions(self, portion_structure):

        self.recurse_hash_partial_tree(portion_structure)

        return portion_structure.hash == self.root_node.hash

    def recurse_hash_partial_tree(self, current_node):

        if current_node.hash is not None:
            self.partial_hash_tree_bandwith = self.partial_hash_tree_bandwith + 1

        if current_node.hasChildren and current_node.hash is None:
            for ii in current_node.children:
                self.recurse_hash_partial_tree(current_node.children[ii])

            current_node.computeSelfHash()
            self.hash_count = self.hash_count + 1

    def count_nonzero_hashes_recurse(self, current_node):
        if current_node.hash is not None:
            self.partial_hash_tree_bandwith = self.partial_hash_tree_bandwith + 1

        for ii in current_node.children:
            self.count_nonzero_hashes_recurse(current_node.children[ii])

        return self.partial_hash_tree_bandwith

    def count_nonzero_hashes(self):
        self.partial_hash_tree_bandwith = 0
        return self.count_nonzero_hashes_recurse(self, self.root_node)

    # Reset the metrics
    def reset_metrics(self):
        self.hash_count = 0
        self.byte_io_count = 0
        self.partial_hash_tree_bandwith = 0
        self.num_hashes_calculated = 0

        # Return a hash of the given bytes,
    #   also maintain a count of how many hashes
    #   are computed.
    def compute_bytes_hash(self, bytes_to_hash):
        m = hashlib.sha256()
        m.update(bytes_to_hash)

        self.hash_count = self.hash_count + 1

        return m.digest()

    # Read bytes from a file,
    #   also maintain a count of how many
    #   bytes are read from the file.
    def read_bytes_from_file(self, file_object, num_bytes):

        bytes = file_object.read(num_bytes)

        self.byte_io_count = self.byte_io_count + len(bytes)

        return bytes

    # Groups the list of input nodes into groups of two
    #   and returns a new list of nodes whose children
    #   are those groups of two
    def make_tree_level(self, node_list):

        parent_nodes = list()
        cur_parent_node = merkle_node(-1)
        parent_nodes.append(cur_parent_node)
        for node in node_list:
            if cur_parent_node.numChildren() >= 2:
                cur_parent_node = merkle_node(-1)
                parent_nodes.append(cur_parent_node)

            cur_parent_node.addChild(node)

        return parent_nodes

