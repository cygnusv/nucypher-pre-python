from functools import reduce

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec


from hazmat_math import operations as ops


# minVal = (1 << 256) % self.order   (i.e., 2^256 % order)
MINVAL_SECP256K1_HASH_256 = 432420386565659656852420866394968145599

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
    def __init__(self, id, key, xcomp, u1, z1, z2):
        self.id = id
        self.key = key
        self.xcomp = xcomp
        self.u1 = u1
        self.z1 = z1
        self.z2 = z2


class CiphertextKEM(object):
    def __init__(self, e, v, s):
        self.e = e
        self.v = v
        self.s = s


class CiphertextFrag(object):
    def __init__(self, e_r, v_r, id_r, x):
        self.e_r = e_r
        self.v_r = v_r
        self.id_r = id_r
        self.x = x

class CiphertextCombined(object):
    def __init__(self, e, v, x, u1, z1, z2):
        self.e = e
        self.v = v
        self.x = x
        self.u1 = u1
        self.z1 = z1
        self.z2 = z2


class ChallengeResponse(object):
    def __init__(self, e_t, v_t, u1, u2, z1, z2, z3)
        self.e_r = e_r
        self.v_r = v_r
        self.u1 = u1
        self.u2 = u2
        self.z1 = z1
        self.z2 = z2
        self.z3 = z3


class PRE(object):
    def __init__(self):
        self.backend = default_backend()
        self.curve = ec.SECP256K1()
        self.g = ops.EC_GET_GENERATOR(self.curve)
        self.order = ops.EC_GET_ORDER(self.curve)

    def hash_to_Zq(self, list):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    for x in list:
        if x is _EllipticCurvePublicKey:
            bytes  = x.public_numbers().encode_point()
        elif x is _EllipticCurvePrivateKey:
            bytes  = x.private_numbers().private_value
        elif:
            bytes = x
        digest.update(bytes)
    
    i = 0
    h = 0
    while h < MINVAL_SECP256K1_HASH_256:
        digest_i = digest.copy()
        digest_i.update(i.to_bytes(32, byteorder='big'))
        hash = digest_i.finalize()
        #h = int.from_bytes(hash, byteorder='big', signed=False)
        i += 1

    hash_bn = ops.bytes_to_BN(hash)
    return ops.BN_MOD(hash_bn, self.order)


    def gen_priv(self):
        return ec.generate_private_key(ec.SECP256K1(), default_backend())

    def rekey(self, priv_a, priv_b):
        rk_ab = ops.BN_MOD_MUL(priv_a, ops.BN_MOD_INVERSE(priv_b))
        return RekeyFrag(None, rk_ab)

    def split_rekey(self, priv_a, priv_b, threshold, N):
        coeffs = [self.rekey(priv_a, priv_b)]
        coeffs += [self.gen_priv() for _ in range(threshold - 1)]

        vKeys = [ops.EC_POINT_MUL(self.g, coeff) for coeff in coeffs]

        ids = [self.gen_priv() for _ in range(N)]
        rk_shares = [RekeyFrag(id, key=poly_eval(coeffs, id)) for id in ids]

        return rk_shares, vKeys

    def combine(self, cipher_frags):
        if len(cipher_frags) > 1:
            ids = [cfrag.re_id for cfrag in cipher_frags]
            map_list = [
                ops.EC_POINT_MUL(cfrag.key, lambda_coeff(cfrag.re_id, ids))
                for cfrag in cipher_frags
            ]
            product = reduce(ops.EC_POINT_ADD, map_list)
            return CiphertextKEM(product)
        elif len(cipher_frags) == 1:
            return CiphertextKEM(cipher_frags[0].key)

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

        return (key, CiphertextKEM(pub_e))

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
