import hashlib
import random
class sPOW:
    def __init__(self, local_file_path):
        self.file_pointer = local_file_path
        self.challenges = []
        self.num_challenges_computed = 0
        self.num_challenges_used = 0
        self.seeds = []

    def numOFUnusedChallenges(self):
        return self.num_challenges_computed - self.num_challenges_used
