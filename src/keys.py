from secp256k1 import G, N, Signature
from helper import hash256

from hashlib import sha256
import hmac


class PrivateKey:
    """Models EC private key"""
    def __init__(self, secret):
        self.secret = secret
        self.point = secret * G  # point on an Elliptic Curve/ Public Key

    def __repr__(self):
        return "Brah it's a secret!"

    def hex(self):
        return '{:x}'.format(self.secret).zfill(64)

    def sign(self, msg):
        """Returns signature for a given message, z"""
        z = int.from_bytes(hash256(msg), "big")
        k = self.deterministic_k(z)
        k_inv = pow(k, N-2, N)
        r = (k*G).x.num
        s = (z + r * self.secret) * k_inv % N
        if s > N/2:
            s = N - s

        return Signature(r, s)

    def deterministic_k(self, z):
        """Ensures that we never reuse k values and compromise out secret"""
        k = b'\x00' * 32
        v = b'\x01' * 32
        if z > N:
            z -= N
        z_bytes = z.to_bytes(32, 'big')
        secret_bytes = self.secret.to_bytes(32, 'big')
        s256 = sha256
        k = hmac.new(k, v + b'\x00' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        k = hmac.new(k, v + b'\x01' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        while True:
            v = hmac.new(k, v, s256).digest()
            candidate = int.from_bytes(v, 'big')
            if candidate >= 1 and candidate < N:
                return candidate
            k = hmac.new(k, v + b'\x00', s256).digest()
            v = hmac.new(k, v, s256).digest()
