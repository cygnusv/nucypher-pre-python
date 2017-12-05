from functools import reduce
from operator import mul

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def lambda_coeff(id_i, selected_ids):
    filtered_list = [x for x in selected_ids if x != id_i]
    map_list = [id_j * ~(id_j - id_i) for id_j in filtered_list]
    x = reduce(mul, map_list)
    return x


def poly_eval(coeff, x):
    result = coeff[-1]
    for i in range(-2, -len(coeff) - 1, - 1):
        result = result * x + coeff[i]
    return result


class PRE(object):
    def __init__(self):
        self.backend = default_backend()
        self.curve = ec.SECP256K1()

    def kdf(self, ecdata, key_length):
        return HKDF(
            algorithm=hashes.SHA512(),
            length=key_length,
            salt=None,
            info=None,
            backend=default_backend()
        ).derive(ecdata)

    def gen_priv(self):
        return ec.generate_private_key(ec.SECP256K1(), default_backend())

    def rekey(self, priv_a, priv_b):
        rk_ab = priv_a * (~priv_b)
        return rk_ab

    def reencrypt(self, rk, ekey):
        new_ekey = ekey * rk
        return new_ekey

    def encapsulate(self, pub_key, key_length=32):
        priv_e = self.gen_priv()
        pub_e = priv_e.public_key()

        # ECDH between the ephemeral key and the public key
        shared_key = priv_e.exchange(ec.ECDH(), pub_key)

        # ECIES Symmetric key
        key = self.kdf(shared_key, key_length)

        return (key, pub_e)

    def decapsulate(self, priv_key, enc_key, key_length=32):
        shared_key = priv_key.exchange(ec.ECDH(), enc_key)
        key = self.kdf(shared_key, key_length)
        return key
