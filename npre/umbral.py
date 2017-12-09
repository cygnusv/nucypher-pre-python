from functools import reduce

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from hazmat_math import operations as ops


def lambda_coeff(id_i, selected_ids):
    filtered_list = [x for x in selected_ids if x != id_i]

    map_list = []
    for id_j in filtered_list:
        id_inverse = ops.BN_MOD_INVERSE(ops.BN_MOD_SUB(id_j, id_i))
        map_list.append(ops.BN_MOD_MUL(id_j, id_inverse))

    return reduce(ops.BN_MOD_MUL, map_list)


def poly_eval(coeff, x):
    result = coeff[-1]
    for i in range(-2, -len(coeff) - 1, - 1):
        result = ops.BN_MOD_MUL(result, x)
        result = ops.BN_MOD_ADD(result, coeff[i])
    return result


class RekeyFrag(object):
    def __init__(self, id, key):
        self.id = id
        self.key = key


class CiphertextFrag(object):
    def __init__(self, key, re_id):
        self.key = key
        self.re_id = re_id


class EncryptedKey(object):
    def __init__(self, key):
        self.key = key


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
        rk_ab = ops.BN_MOD_MUL(priv_a, ops.BN_MOD_INVERSE(priv_b))
        return rk_ab

    def split_rekey(self, priv_a, priv_b, threshold, N):
        coeffs = [self.rekey(priv_a, priv_b)]
        coeffs += [self.gen_priv() for _ in range(threshold - 1)]

        ids = [self.gen_priv() for _ in range(N)]
        rk_shares = [RekeyFrag(id, key=poly_eval(coeffs, id)) for id in ids]

        return rk_shares

    def combine(self, cipher_frags):
        if len(cipher_frags) > 1:
            ids = [cfrag.re_id for cfrag in cipher_frags]
            map_list = [
                ops.EC_POINT_MUL(cfrag.key, lambda_coeff(cfrag.re_id, ids))
                for cfrag in cipher_frags
            ]
            product = reduce(ops.EC_POINT_ADD, map_list)
            return EncryptedKey(product)
        elif len(cipher_frags) == 1:
            return EncryptedKey(cipher_frags[0].key)

    def reencrypt(self, rekey_frag, cipher_frag):
        new_ekey = ops.EC_POINT_MUL(cipher_frag.key, rekey_frag.key)
        return CiphertextFrag(new_ekey, rekey_frag.id)

    def encapsulate(self, pub_key, key_length=32):
        priv_e = self.gen_priv()
        pub_e = priv_e.public_key()

        # ECDH between the ephemeral key and the public key
        shared_key = priv_e.exchange(ec.ECDH(), pub_key)

        # ECIES Symmetric key
        key = self.kdf(shared_key, key_length)

        return (key, EncryptedKey(pub_e))

    def decapsulate(self, priv_key, enc_key, key_length=32):
        shared_key = priv_key.exchange(ec.ECDH(), enc_key.key)
        key = self.kdf(shared_key, key_length)
        return key


if __name__ == '__main__':
    pre = PRE()
    priv_a = pre.gen_priv()
    priv_b = pre.gen_priv()

    pub_a = priv_a.public_key()
    pub_b = priv_b.public_key()

    rks = pre.split_rekey(priv_a, priv_b, 2, 3)

    plain1, enc_a = pre.encapsulate(pub_a)
    shares = [pre.reencrypt(rk, enc_a) for rk in rks]
    sec = pre.combine(shares)
