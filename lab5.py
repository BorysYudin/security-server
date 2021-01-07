import argparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import dsa


class DSS:
    def __init__(self):
        self._private_key = None
        self._public_key = None

    def generate_keys(self):
        self._private_key = dsa.generate_private_key(key_size=1024)
        self._public_key = self._private_key.public_key()

    @staticmethod
    def _get_encryption_algorithm(password):
        if not password:
            return serialization.NoEncryption()

        if not isinstance(password, bytes):
            password = str.encode(password)
        return serialization.BestAvailableEncryption(password)

    def serialize_private_key(self, source="key_lab5.pem", password=None):
        pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=self._get_encryption_algorithm(password)
        )

        with open(source, "wb") as f:
            f.write(pem)

    def serialize_public_key(self, source="pub_key_lab5.pem"):
        pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(source, "wb") as f:
            f.write(pem)

    def load_private_key(self, path="./key_lab5.pem", password=None):
        if password and not isinstance(password, bytes):
            password = str.encode(password)

        with open(path, "rb") as key_file:
            self._private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password,
            )

    def load_public_key(self, path="./pub_key_lab5.pem"):
        with open(path, "rb") as key_file:
            self._public_key = serialization.load_pem_public_key(key_file.read())

    def sign_string(self, data):
        return self._private_key.sign(data, hashes.SHA256())

    def sign_file(self, infile):
        chosen_hash = hashes.SHA256()
        hasher = hashes.Hash(chosen_hash)

        with open(infile, "rb") as in_:
            while True:
                text = in_.read(1024)
                if not text:
                    break

                hasher.update(text)

        digest = hasher.finalize()
        signature = self._private_key.sign(
            digest,
            utils.Prehashed(chosen_hash)
        )

        return signature

    def verify_string(self, data, sign_file):
        with open(sign_file, "rb") as sig_in:
            sign = sig_in.read()

        return self._public_key.verify(sign, data, hashes.SHA256())

    def verify_file(self, infile, sign_file):
        chosen_hash = hashes.SHA256()
        hasher = hashes.Hash(chosen_hash)

        with open(infile, "rb") as in_, open(sign_file, "rb") as sig_in:
            sign = sig_in.read()
            while True:
                text = in_.read(1024)
                if not text:
                    break

                hasher.update(text)

        digest = hasher.finalize()
        return self._public_key.verify(sign, digest, utils.Prehashed(chosen_hash))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-g", "--generate-keys", action="store_true")
    parser.add_argument("-i", "--infile")
    parser.add_argument("-o", "--outfile")
    parser.add_argument("-s", "--secret")
    parser.add_argument("-t", "--text")
    parser.add_argument("--sig")
    parser.add_argument("-a", "--action", choices=('sign', 'verify'))

    args = parser.parse_args()

    dss = DSS()

    if args.generate_keys:
        dss.generate_keys()
        dss.serialize_private_key(password=args.secret)
        dss.serialize_public_key()

    if args.action == "sign":
        dss.load_private_key(password=args.secret)
        signature = None

        if args.text:
            signature = dss.sign_string(args.text.encode())
        elif args.infile:
            signature = dss.sign_file(args.infile)

        print(f"Signature: \n {signature}")
        if args.outfile:
            with open(args.outfile, "wb") as out_:
                out_.write(signature)

    elif args.action == "verify":
        dss.load_public_key()

        try:
            if args.text:
                is_valid = dss.verify_string(args.text.encode(), args.sig)
            elif args.infile:
                is_valid = dss.verify_file(args.infile, args.sig)
        except InvalidSignature:
            print(f"Signature is NOT valid")
        else:
            print(f"Signature is valid")
