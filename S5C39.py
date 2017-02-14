from Crypto.Util.number import getPrime


def int_to_bytes(n):
    """Converts the given int n to bytes and returns them."""
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')


def gcd(a, b):
    """Computes the greatest common divisor between a and b using the Euclidean algorithm."""
    while b != 0:
        a, b = b, a % b

    return a


def lcm(a, b):
    """Computes the lowest common multiple between a and b using the GCD method."""
    return a // gcd(a, b) * b


def mod_inv(a, n):
    """Computes the multiplicative inverse of a modulo n using the extended Euclidean algorithm."""
    t, r = 0, n
    new_t, new_r = 1, a

    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r

    if r > 1:
        raise Exception("a is not invertible")
    if t < 0:
        t = t + n

    return t


class RSA:
    """Implements the RSA public key encryption / decryption."""

    def __init__(self, key_length):
        """In this exercise, e is fixed to 3 so we will have to find p and q that fit the requirements."""
        self.e = 3
        phi = 0

        while gcd(self.e, phi) != 1:
            p, q = getPrime(key_length // 2), getPrime(key_length // 2)
            phi = lcm(p - 1, q - 1)
            self.n = p * q

        self._d = mod_inv(self.e, phi)

    def encrypt(self, binary_data):
        """Converts the input bytes to an int (bytes -> int) and then encrypts the int with RSA."""
        int_data = int.from_bytes(binary_data, byteorder='big')
        return pow(int_data, self.e, self.n)

    def decrypt(self, encrypted_int_data):
        """Decrypts the encrypted input data to an int and then converts it back to bytes (int -> bytes)."""
        int_data = pow(encrypted_int_data, self._d, self.n)
        return int_to_bytes(int_data)


def main():

    # Check that the implementation of mod inv is correct
    assert mod_inv(17, 3120) == 2753

    # Check that the implementation of RSA is correct
    rsa = RSA(1024)
    some_text = b"Hello, let's try if the RSA code works"
    assert rsa.decrypt(rsa.encrypt(some_text)) == some_text


if __name__ == '__main__':
    main()
