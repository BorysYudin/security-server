import argparse

from time import time
from functools import partial

from helpers import profile
from main import MD5, Rand

rand = Rand(1103515245, int(time()) % 2**31, 12345, 2**31)

i_from_b = partial(int.from_bytes, byteorder='little')


class RC5:
    CONST = {
        16: (0xB7E1, 0x9E37),
        32: (0xB7E15163, 0x9E3779B9),
        64: (0xB7E151628AED2A6B, 0x9E3779B97F4A7C15)
    }

    def __init__(self, word_size, rounds, key_bytes, secret):
        self.word_size = word_size
        self.rounds = rounds
        self.key_bytes = key_bytes
        self.secret = secret

        self.key = self._get_key()
        self._align_key()

        self.C = len(self.key) // self._word_bytes

        self.L = self._get_L()
        self.S = self._get_S()
        self._mix_L_S()

        self.BYTES_TO_READ = (2 * self.word_size) // 8

    @property
    def _word_bytes(self):
        return self.word_size // 8

    def _get_key(self):
        key = str.encode(MD5(self.secret).generate())
        if self.key_bytes <= 16:
            key = key[:self.key_bytes]
        else:
            while len(key) < self.key_bytes:
                key = str.encode(MD5(key).generate()) + key
            key = key[:self.key_bytes]

        return key

    def _align_key(self):
        while len(self.key) % self._word_bytes:
            self.key += b"\x00"

    def _get_L(self):
        L = []
        for i in range(0, len(self.key), self._word_bytes):
            L.append(i_from_b(self.key[i:i + self._word_bytes]))

        return L

    def _get_S(self):
        P, Q = self.CONST[self.word_size]
        S = [P]

        for i in range(1, 2 * self.rounds + 2):
            S.append((S[i - 1] + Q) % 2 ** self.word_size)

        return S

    def _mix_L_S(self):
        t = max(self.C, 2 * self.rounds + 2)
        A = B = i = j = 0

        for k in range(3 * t):
            A = self.S[i] = self._shift_left(self.S[i] + A + B, 3)
            B = self.L[j] = self._shift_left(self.L[j] + A + B, A + B)

            i = (i + 1) % (2 * self.rounds + 1)
            j = (j + 1) % self.C

    def _shift_left(self, val, shift_bits):
        max_bits = self.word_size
        v1 = (val << shift_bits % max_bits) & (2 ** max_bits - 1)
        v2 = ((val & (2 ** max_bits - 1)) >> (max_bits - (shift_bits % max_bits)))
        return v1 | v2

    def _shift_right(self, val, shift_bits):
        max_bits = self.word_size
        v1 = ((val & (2 ** max_bits - 1)) >> shift_bits % max_bits)
        v2 = (val << (max_bits - (shift_bits % max_bits)) & (2 ** max_bits - 1))
        return v1 | v2

    def _i2b(self, value):
        return value.to_bytes(self._word_bytes, byteorder='little')

    def _encrypt_block(self, A, B):
        A = (A + self.S[0]) % 2 ** self.word_size
        B = (B + self.S[1]) % 2 ** self.word_size
        for i in range(1, self.rounds):
            A = (self._shift_left((A ^ B), B) + self.S[2 * i]) % 2 ** self.word_size
            B = (self._shift_left((B ^ A), A) + self.S[2 * i + 1]) % 2 ** self.word_size

        return A, B

    def _generate_iv(self, out_file):
        A_, B_ = rand(), rand()

        A, B = self._encrypt_block(A_, B_)

        with open(out_file, 'wb') as out:
            out.write(self._i2b(A) + self._i2b(B))

        return A_, B_

    @profile
    def encrypt(self, in_file, out_file):
        prev_A, prev_B = self._generate_iv(out_file)
        with open(in_file, 'rb') as inp, open(out_file, 'ab') as out:
            text = inp.read(self.BYTES_TO_READ)
            end_text = False

            while True:
                if not text:
                    end_text = True
                    text = b""
                elif len(text) < self.BYTES_TO_READ:
                    end_text = True
                    text = text.ljust(self.BYTES_TO_READ, bytes([self.BYTES_TO_READ - len(text)]))

                A = i_from_b(text[:self._word_bytes]) ^ prev_A
                B = i_from_b(text[self._word_bytes:]) ^ prev_B
                prev_A, prev_B = A, B

                A, B = self._encrypt_block(A, B)

                out.write(self._i2b(A) + self._i2b(B))
                if end_text:
                    break
                text = inp.read(self.BYTES_TO_READ)

    def _decrypt_block(self, text):
        A = i_from_b(text[:self._word_bytes])
        B = i_from_b(text[self._word_bytes:])
        for i in range(self.rounds - 1, 0, -1):
            B = self._shift_right(
                ((B - self.S[2 * i + 1]) % 2 ** self.word_size), A) ^ A
            A = self._shift_right(
                ((A - self.S[2 * i]) % 2 ** self.word_size), B) ^ B

        A = (A - self.S[0]) % 2 ** self.word_size
        B = (B - self.S[1]) % 2 ** self.word_size

        return A, B

    @profile
    def decrypt(self, in_file, out_file):
        with open(in_file, 'rb') as inp, open(out_file, 'wb') as out:
            # Get iv from first block
            text = inp.read(self.BYTES_TO_READ)
            prev_A, prev_B = self._decrypt_block(text)

            # Process other blocks
            prev_block = inp.read(self.BYTES_TO_READ)

            while True:
                if not prev_block:
                    break
                next_block = inp.read(self.BYTES_TO_READ)

                A, B = self._decrypt_block(prev_block)

                temp_A, temp_B = A, B
                A = A ^ prev_A
                B = B ^ prev_B
                prev_A = temp_A
                prev_B = temp_B
                res = (self._i2b(A) + self._i2b(B))

                if not next_block:
                    # Strip added bytes. res[-1] is amount of added bytes
                    res = res[:-res[-1]]

                out.write(res)

                prev_block = next_block


if __name__ == "__main__":
    def check_range(value):
        value = int(value)
        if not (0 <= value <= 255):
            raise argparse.ArgumentTypeError(f"{value} is an invalid positive int value")
        return value

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--infile")
    parser.add_argument("-o", "--outfile")
    parser.add_argument("-s", "--secret", required=True)
    parser.add_argument("-k", "--keybytes", type=check_range, required=True)
    parser.add_argument("-r", "--rounds", type=check_range, default=16)
    parser.add_argument("-w", "--wordsize", type=int, default=32, choices=[16, 32, 64])
    parser.add_argument("-a", "--action", required=True, choices=('encrypt', 'decrypt'))

    args = parser.parse_args()

    rc5 = RC5(args.wordsize, args.rounds, args.keybytes, args.secret)
    getattr(rc5, args.action)(args.infile, args.outfile)
