# Lab 1
A = 5 ** 3
X0 = 512
C = 34
M = 2**18 - 1


class Rand:
    def __init__(self, a, x0, c, m):
        self.a = a
        self.next = x0
        self.c = c
        self.m = m

    def __call__(self, *args, **kwargs):
        self.next = (self.a * self.next + self.c) % self.m
        return self.next

    @staticmethod
    def get_sequence_period(sequence):
        period = 1

        while len(set(sequence[:period])) == len(sequence[:period]) and period <= len(sequence):
            period += 1

        return period - 1


if __name__ == "__main__":
    rand = Rand(A, X0, C, M)
    count = int(input("Enter number of values: "))

    generated_sequence = [rand() for _ in range(count)]

    with open("random_sequence.csv", "w+") as file_:
        file_.write(",".join(map(str, generated_sequence)))

    if len(generated_sequence) <= 100:
        print(generated_sequence)

    print(f"Period: {Rand.get_sequence_period(generated_sequence)}")

# Lab 2
import argparse

import math
import struct
from functools import partial
from os import path

from bitarray import bitarray


class MD5:
    STAGES = 4
    ROUNDS = 16

    def __init__(self, msg):
        self.stream = bitarray(endian="big")
        data = msg if type(msg) == bytes else msg.encode("utf-8")
        self.stream.frombytes(data)
        self.origin_len = len(self.stream)
        self.T = []
        self.buffers = {}
        self.s = [
            [7, 12, 17, 22],
            [5, 9, 14, 20],
            [4, 11, 16, 23],
            [6, 10, 15, 21],
        ]

        for i in range(64):
            self.T.append(int(2**32 * abs(math.sin(i + 1))))

    def generate(self):
        self.step1()
        self.step2()
        self.step3()
        self.step4()
        return self.step5()

    def step1(self):
        self.stream.append(1)
        while len(self.stream) % 512 != 448:
            self.stream.append(0)

        self.stream = bitarray(self.stream, endian="little")

    def step2(self):
        len_arr = bitarray(endian="little")
        len_arr.frombytes(struct.pack("<q", self.origin_len % pow(2, 64)))
        self.stream.extend(len_arr)

    def step3(self):
        self.buffers = {
            "A": int("67452301", 16),
            "B": int("EFCDAB89", 16),
            "C": int("98BADCFE", 16),
            "D": int("10325476", 16),
        }

    def step4(self):
        for chunk in self.stream_chunks_generator(self.stream):
            A, B, C, D = self.run_rounds(chunk)
            self.buffers["A"] = self.m_add(self.buffers["A"], A)
            self.buffers["B"] = self.m_add(self.buffers["B"], B)
            self.buffers["C"] = self.m_add(self.buffers["C"], C)
            self.buffers["D"] = self.m_add(self.buffers["D"], D)

    def step5(self):
        A = int.from_bytes(struct.pack(">I", self.buffers["A"]), "little")
        B = int.from_bytes(struct.pack(">I", self.buffers["B"]), "little")
        C = int.from_bytes(struct.pack(">I", self.buffers["C"]), "little")
        D = int.from_bytes(struct.pack(">I", self.buffers["D"]), "little")

        return f"{format(A, '08x')}{format(B, '08x')}{format(C, '08x')}{format(D, '08x')}"

    def run_rounds(self, chunk):
        M = self.break_chunk_to_words(chunk)

        A = self.buffers["A"]
        B = self.buffers["B"]
        C = self.buffers["C"]
        D = self.buffers["D"]

        for stage in range(self.STAGES):
            stage_func = getattr(self, f"stage{stage + 1}")
            for round_ in range(self.ROUNDS):
                iteration = stage * self.ROUNDS + round_
                g, f = stage_func(B, C, D, iteration)

                f = self.m_add(f, self.m_add(A, self.m_add(self.T[iteration], M[g])))
                A, D, C = D, C, B
                B = self.m_add(B, self.rotate_bits_left(f, self.s[stage][round_ % 4]))

        return A, B, C, D

    def stage1(self, x, y, z, iteration):
        return iteration, self.F(x, y, z)

    def stage2(self, x, y, z, iteration):
        return ((5 * iteration) + 1) % 16, self.G(x, y, z)

    def stage3(self, x, y, z, iteration):
        return ((3 * iteration) + 5) % 16, self.H(x, y, z)

    def stage4(self, x, y, z, iteration):
        return (7 * iteration) % 16, self.I(x, y, z)

    @staticmethod
    def F(x, y, z):
        return (x & y) | (~x & z)

    @staticmethod
    def G(x, y, z):
        return (x & z) | (y & ~z)

    @staticmethod
    def H(x, y, z):
        return x ^ y ^ z

    @staticmethod
    def I(x, y, z):
        return y ^ (x | ~z)

    @staticmethod
    def rotate_bits_left(bits, count):
        return (bits << count) | (bits >> (32 - count))

    @staticmethod
    def m_add(a, b):
        return (a + b) % pow(2, 32)

    @staticmethod
    def stream_chunks_generator(stream, size=512):
        chunks_amount = len(stream) // size
        for i in range(chunks_amount):
            yield stream[i * size:(i + 1) * size]

    @staticmethod
    def break_chunk_to_words(chunk):
        to_int = partial(int.from_bytes, byteorder="little")
        words = [to_int(chunk[(x * 32):(x + 1) * 32]) for x in range(16)]
        return words


def read_file_data(file_):
    try:
        with open(file_) as f:
            return f.read()
    except UnicodeDecodeError:
        with open(file_, "rb") as f:
            return f.read()


def check_file_integrity(hash_file, hash_):
    with open(hash_file) as hf:
        validation_hash = hf.read()

    print("File is valid" if validation_hash == hash_ else "File is corrupted")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file")
    parser.add_argument("-H", "--hash_file")
    parser.add_argument("-s", "--string")
    parser.add_argument("-o", "--output")

    args = parser.parse_args()

    if args.file and path.exists(args.file):
        data = read_file_data(args.file)
        file_data_hash = MD5(data).generate()

        if args.hash_file and path.exists(args.hash_file):
            check_file_integrity(args.hash_file, file_data_hash)

        if args.output:
            with open(args.output, "w") as f:
                f.write(file_data_hash)

        print(f"File hash: {file_data_hash}")

    if args.string:
        s = "" if args.string == "''" else args.string
        str_hash = MD5(s).generate()

        print(f"String hash: {str_hash}")

    # print(MD5("").generate() == "D41D8CD98F00B204E9800998ECF8427E".lower())
    # print(MD5("a").generate() == "0cc175b9c0f1b6a831c399e269772661")
    # print(MD5("abc").generate() == "900150983CD24FB0D6963F7D28E17F72".lower())
    # print(MD5("message digest").generate() == "F96B697D7CB7938D525A2F31AAF161D0".lower())
    # print(MD5("abcdefghijklmnopqrstuvwxyz").generate() == "C3FCD3D76192E4007DFB496CCA67E13B".lower())
    # print(MD5("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").generate() == "D174AB98D277D9F5A5611C2C9F419D9F".lower())
    # print(MD5("12345678901234567890123456789012345678901234567890123456789012345678901234567890").generate() == "57EDF4A22BE3C955AC49DA2E2107B67A".lower())
