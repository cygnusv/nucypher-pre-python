from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends.openssl.ec import (
    _EllipticCurvePrivateKey, _EllipticCurvePublicKey
)



def kdf(self, ecdata, key_length):
    return HKDF(
        algorithm=hashes.SHA512(),
        length=key_length,
        salt=None,
        info=None,
        backend=default_backend()
    ).derive(ecdata)

