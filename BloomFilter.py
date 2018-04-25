from bitarray import bitarray
import mmh3

class BloomFilter:

    def __init__(self, size, hash_count):
        self.size = size
        self.hash_count = int(hash_count)
        self.bit_array = bitarray(size)
        self.bit_array.setall(0)

    def add(self, text):
        for i in range(self.hash_count):
            hashresult = mmh3.hash(text, i) % self.size
            self.bit_array[hashresult] = True

    def check(self, text):
        for i in range(self.hash_count):
            hashresult = mmh3.hash(text, i) % self.size
            if self.bit_array[hashresult] == False:
                return False
        return True

    def retrieve(self, text):
        for i in range(self.hash_count):
            hashresult = mmh3.hash(text, i) % self.size
            if self.bit_array[hashresult] == False:
                return hashresult
        return ''
