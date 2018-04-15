import hashlib

class merkle_node:

    def __init__(self):

        self.hash = None
        self.children = dict()
        self.parent = None

    def addChild(self, childNode):

        self.children[childNode.hash] = childNode
        childNode.parent = self

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

    # Initializes the data structure for the given file
    def __init__(self, local_file_path):

        self.local_file_path = local_file_path
        self.file_portion_dictionary = dict()
        self.portion_hash_dictionary = dict()
        self.portion_node_dictionary = dict()
        node_list = list()

        m = hashlib.sha256()
        with open(local_file_path, "rb") as f:

            file_portion_id = 1
            bytes = f.read(self.chunk_size)
            while bytes != b"":
                # Compute the hash of the bytes of each portion
                self.portion_hash_dictionary[file_portion_id] = self.compute_bytes_hash(bytes)

                # Set the portion bytes
                self.file_portion_dictionary[file_portion_id] = bytes

                # Update the whole file hash with the current bytes
                m.update(bytes)

                # Update the list of file portion nodes
                portion_node = merkle_node()
                portion_node.hash = self.portion_hash_dictionary[file_portion_id]
                node_list.append(portion_node)
                self.portion_node_dictionary[file_portion_id] = portion_node

                # Increment for the next portion and read the next chunk
                file_portion_id = file_portion_id + 1
                bytes = f.read(self.chunk_size)

        self.whole_file_hash = m.digest()

        latest_node_list = node_list
        while len(latest_node_list) != 1:
            latest_node_list = self.make_tree_level(latest_node_list)

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
        num_portions = 10
        if num_portions > self.get_num_portions():
            num_portions = self.get_num_portions()
        return num_portions

    # Return a hash of the given bytes
    def compute_bytes_hash(self, bytes_to_hash):
        m = hashlib.sha256()
        m.update(bytes_to_hash)

        return m.digest()

    # Groups the list of input nodes into groups of two
    #   and returns a new list of nodes whose children
    #   are those groups of two
    def make_tree_level(self, node_list):

        parent_nodes = list()
        cur_parent_node = merkle_node()
        parent_nodes.append(cur_parent_node)
        for node in node_list:
            if cur_parent_node.numChildren() >= 2:
                cur_parent_node = merkle_node()
                parent_nodes.append(cur_parent_node)

            cur_parent_node.addChild(node)

        return parent_nodes
