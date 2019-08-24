from elliptic_curve import Point
from field_element import FieldElement
from helper import hash256

from hashlib import sha256
import hmac


# constants for secp256k1
# secp256k1: y**2 = x**3 + 7
A, B = 0, 7

# PRIME is the order of the Finite Field
PRIME = 2**256 - 2**32 - 977

# N is order of the finite cyclical group
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

# GX is the x coord of generator point
GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
# GY is the y coord of generator point
GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

class S256Field(FieldElement):
    """
    specific to the EC used in Bitcoin
    secp256k1: y**2 = x**3 + 7
    """
    def __init__(self, num, prime=None):
        super().__init__(num=num, prime=PRIME)

    def __repr__(self):
        return '{:x}'.format(self.num).zfill(64)


class S256Point(Point):
    """For all intents and purposes this is our public key class"""
    def __init__(self, x, y, a=None, b=None):
        a, b = S256Field(A), S256Field(B)
        if type(x) == int:
            super().__init__(x=S256Field(x), y=S256Field(y), a=a, b=b)
        else:
            super().__init__(x=x, y=y, a=a, b=b)

    def __rmul__(self, coefficient):
        coef = coefficient % N
        return super().__rmul__(coef)

    def verify(self, z=None, signature=None):
        """
        verify a signature where self is the public key
        """
        s_inv = pow(signature.s, N-2, N)
        u = z * s_inv % N
        v = signature.r * s_inv % N
        R = (u * G) + (v * self)
        return R.x.num == signature.r

    def sec(self, compressed=True):
        '''returns the binary version of the SEC format'''
        if compressed:
            if self.y.num % 2 == 0:
                return b'\x02' + self.x.num.to_bytes(32, 'big')
            else:
                return b'\x03' + self.x.num.to_bytes(32, 'big')
        else:
            return b'\x04' + self.x.num.to_bytes(32, 'big') + self.y.num.to_bytes(32, 'big')

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


# G is the generator Point
G = S256Point(GX, GY)

class Signature:
    """
    Houses signature values r & s (like the record label)
    """
    def __init__(self, r, s):
        self.r = r
        self.s = s

    def __repr__(self):
        return 'Signature({:x},{:x})'.format(self.r, self.s)