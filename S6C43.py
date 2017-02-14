from S5C39 import mod_inv
from S4C28 import sha1
from random import randint


class DSA:
    """Implements the DSA public key encryption / decryption."""
    DEFAULT_P = int("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76"
                    "c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232"
                    "c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16)
    DEFAULT_Q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    DEFAULT_G = int("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389"
                    "b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c88"
                    "7892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16)

    def __init__(self, q=DEFAULT_Q, p=DEFAULT_P, g=DEFAULT_G):
        self.q = q
        self.p = p
        self.g = g
        self._x = randint(1, self.q - 1)
        self.y = pow(self.g, self._x, self.p)

    @staticmethod
    def H(message):
        return int(sha1(message), 16)

    def sign(self, message):

        while True:
            k = randint(1, self.q - 1)
            r = pow(self.g, k, self.p) % self.q
            if r == 0:
                continue

            s = (mod_inv(k, self.q) * (self.H(message) + self._x * r)) % self.q
            if s != 0:
                break

        return r, s

    def verify(self, message, r, s):

        if not (0 < r < self.q) or not (0 < s < self.q):
            return False

        w = mod_inv(s, self.q)
        u1 = (self.H(message) * w) % self.q
        u2 = (r * w) % self.q

        t1 = pow(self.g, u1, self.p)
        t2 = pow(self.y, u2, self.p)
        v = ((t1 * t2) % self.p) % self.q

        return v == r


def get_x_from_k(q, k, r, s, hash_of_message):
    """Recovers the private key x given the k sub-key used for the DSA signatures."""
    return (((s * k) - hash_of_message) * mod_inv(r, q)) % q


def key_recovery_from_nonce(r, s, hash_of_message, y):
    """Finds the DSA private key x given the the DSA signature of a given message, by brute forcing
    the value of the sub-key k, which we know was chosen among a small range.
    """

    # Try all possible values of k
    for k in range(2 ** 16):
        x = get_x_from_k(DSA.DEFAULT_Q, k, r, s, hash_of_message)

        # If the private key x corresponding to the current k generates the correct public key, return it
        if pow(DSA.DEFAULT_G, x, DSA.DEFAULT_P) == y:
            return x


def main():

    # Check that the implementation of DSA is correct
    dsa = DSA()
    r, s = dsa.sign(b"hello")
    assert dsa.verify(b"hello", r, s)

    # Given the following values, we can recover the private key x, when k is chosen among a small range
    message = b"For those that envy a MC it can be hazardous to your health\n" \
              b"So be friendly, a matter of life and death, just like a etch-a-sketch\n"
    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940
    y = int("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a0808"
            "4056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec56828"
            "0ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17", 16)

    # Verify that the attack works and that the hacked private key produces the correct fingerprint
    hacked_x = key_recovery_from_nonce(r, s, DSA.H(message), y)
    c = hex(hacked_x)[2:].encode()
    assert sha1(c) == "0954edd5e0afe5542a4adf012611a91912a3ec16"


if __name__ == '__main__':
    main()
