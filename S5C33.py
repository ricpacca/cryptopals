from random import randint


def modular_pow(base, exponent, modulus):
    """Computes (base**exponent) % modulus by using the right-to-left binary method."""
    if modulus == -1:
        return 0

    result = 1
    base %= modulus

    while exponent > 0:
        if exponent % 2:
            result = (result * base) % modulus
        exponent >>= 1
        base = (base * base) % modulus

    return result


class DiffieHellman():
    """Implements the Diffie-Helman key exchange. Each class is a party, which has his secret key (usually
    referred to as lowercase a or b) shares the public key (usually referred to as uppercase A or B) and can
    compute the shared secret key between itself and another party, given their public key, assuming that
    they are agreeing on the same p and g.
    """

    DEFAULT_G = 2
    DEFAULT_P = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b225'
                    '14a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f4'
                    '4c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc20'
                    '07cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed5'
                    '29077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 16)

    def __init__(self, g=DEFAULT_G, p=DEFAULT_P):
        self.g = g
        self.p = p
        self._secret_key = randint(0, p - 1)
        self.shared_key = None

    def get_public_key(self):
        return modular_pow(self.g, self._secret_key, self.p)

    def get_shared_secret_key(self, other_party_public_key):
        if self.shared_key is None:
            self.shared_key = modular_pow(other_party_public_key, self._secret_key, self.p)
        return self.shared_key


def main():
    dh1 = DiffieHellman()
    dh2 = DiffieHellman()

    # Check that our DiffieHellman implementation works and two parties will agree on the same key
    assert dh1.get_shared_secret_key(dh2.get_public_key()) == dh2.get_shared_secret_key(dh1.get_public_key())


if __name__ == '__main__':
    main()
