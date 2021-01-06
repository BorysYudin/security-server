# import argparse
#
# from cryptography.hazmat.primitives.asymmetric import rsa, padding
# from cryptography.hazmat.primitives import serialization, hashes
#
# from helpers import profile
#
#
# class RSA:
#     def __init__(self):
#         self._private_key = None
#         self._public_key = None
#
#     def generate_keys(self):
#         self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
#         self._public_key = self._private_key.public_key()
#
#     @staticmethod
#     def _get_encryption_algorithm(password):
#         if not password:
#             return serialization.NoEncryption()
#
#         if not isinstance(password, bytes):
#             password = str.encode(password)
#         return serialization.BestAvailableEncryption(password)
#
#     def serialize_private_key(self, source="key.pem", password=None):
#         pem = self._private_key.private_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PrivateFormat.PKCS8,
#             encryption_algorithm=self._get_encryption_algorithm(password)
#         )
#
#         with open(source, "wb") as f:
#             f.write(pem)
#
#     def serialize_public_key(self, source="pub_key.pem"):
#         pem = self._public_key.public_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PublicFormat.SubjectPublicKeyInfo
#         )
#
#         with open(source, "wb") as f:
#             f.write(pem)
#
#     def load_private_key(self, path="./key.pem", password=None):
#         if password and not isinstance(password, bytes):
#             password = str.encode(password)
#
#         with open(path, "rb") as key_file:
#             self._private_key = serialization.load_pem_private_key(
#                 key_file.read(),
#                 password=password,
#             )
#
#     def load_public_key(self, path="./pub_key.pem"):
#         with open(path, "rb") as key_file:
#             self._public_key = serialization.load_pem_public_key(key_file.read())
#
#     def encrypt_data(self, data):
#         cipher_text = self._public_key.encrypt(
#             data,
#             padding.OAEP(
#                 mgf=padding.MGF1(algorithm=hashes.SHA256()),
#                 algorithm=hashes.SHA256(),
#                 label=None,
#             )
#         )
#
#         return cipher_text
#
#     @profile
#     def encrypt_file(self, infile, outfile):
#         with open(infile, "rb") as in_, open(outfile, "wb") as out_:
#             cipher_text = self.encrypt_data(in_.read())
#             out_.write(cipher_text)
#
#     def decrypt_data(self, data):
#         plain_text = self._private_key.decrypt(
#             data,
#             padding.OAEP(
#                 mgf=padding.MGF1(algorithm=hashes.SHA256()),
#                 algorithm=hashes.SHA256(),
#                 label=None,
#             )
#         )
#
#         return plain_text
#
#     @profile
#     def decrypt_file(self, infile, outfile):
#         with open(infile, "rb") as in_, open(outfile, "wb") as out_:
#             cipher_text = self.decrypt_data(in_.read())
#             out_.write(cipher_text)
#
#
# if __name__ == "__main__":
#     parser = argparse.ArgumentParser()
#     parser.add_argument("-g", "--generate-keys", action="store_true")
#     parser.add_argument("-i", "--infile")
#     parser.add_argument("-o", "--outfile")
#     parser.add_argument("-s", "--secret")
#     parser.add_argument("-a", "--action", choices=('encrypt', 'decrypt'))
#
#     args = parser.parse_args()
#
#     rsa_ = RSA()
#
#     if args.generate_keys:
#         rsa_.generate_keys()
#         rsa_.serialize_private_key(password=args.secret)
#         rsa_.serialize_public_key()
#
#     if args.action == "encrypt":
#         rsa_.load_public_key()
#         rsa_.encrypt_file(args.infile, args.outfile)
#     elif args.action == "decrypt":
#         rsa_.load_private_key(password=args.secret)
#         rsa_.decrypt_file(args.infile, args.outfile)

import argparse

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

from helpers import profile


class RSA:
    def __init__(self):
        self._private_key = None
        self._public_key = None

    def generate_keys(self):
        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._public_key = self._private_key.public_key()

    @staticmethod
    def _get_encryption_algorithm(password):
        if not password:
            return serialization.NoEncryption()

        if not isinstance(password, bytes):
            password = str.encode(password)
        return serialization.BestAvailableEncryption(password)

    def serialize_private_key(self, source="key.pem", password=None):
        pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=self._get_encryption_algorithm(password)
        )

        with open(source, "wb") as f:
            f.write(pem)

    def serialize_public_key(self, source="pub_key.pem"):
        pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(source, "wb") as f:
            f.write(pem)

    def load_private_key(self, path="./key.pem", password=None):
        if password and not isinstance(password, bytes):
            password = str.encode(password)

        with open(path, "rb") as key_file:
            self._private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password,
            )

    def load_public_key(self, path="./pub_key.pem"):
        with open(path, "rb") as key_file:
            self._public_key = serialization.load_pem_public_key(key_file.read())

    def encrypt_data(self, data):
        cipher_text = self._public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            )
        )

        return cipher_text

    @profile
    def encrypt_file(self, infile, outfile):
        with open(infile, "rb") as in_, open(outfile, "wb") as out_:

            while True:
                text = in_.read(190)
                if not text:
                    break

                cipher_text = self.encrypt_data(text)
                out_.write(cipher_text)

    def decrypt_data(self, data):
        plain_text = self._private_key.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            )
        )

        return plain_text

    @profile
    def decrypt_file(self, infile, outfile):
        with open(infile, "rb") as in_, open(outfile, "wb") as out_:
            while True:
                text = in_.read((self._private_key.key_size + 7) // 8)
                if not text:
                    break

                plain_text = self.decrypt_data(text)
                out_.write(plain_text)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-g", "--generate-keys", action="store_true")
    parser.add_argument("-i", "--infile")
    parser.add_argument("-o", "--outfile")
    parser.add_argument("-s", "--secret")
    parser.add_argument("-a", "--action", choices=('encrypt', 'decrypt'))

    args = parser.parse_args()

    rsa_ = RSA()

    if args.generate_keys:
        rsa_.generate_keys()
        rsa_.serialize_private_key(password=args.secret)
        rsa_.serialize_public_key()

    if args.action == "encrypt":
        rsa_.load_public_key()
        rsa_.encrypt_file(args.infile, args.outfile)
    elif args.action == "decrypt":
        rsa_.load_private_key(password=args.secret)
        rsa_.decrypt_file(args.infile, args.outfile)
