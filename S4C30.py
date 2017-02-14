from random import randint
from binascii import unhexlify, hexlify
from S4C28 import left_rotate
from struct import pack, unpack


class MD4:
    """Adapted from: https://github.com/FiloSottile/crypto.py/blob/master/3/md4.py"""
    buf = [0x00] * 64

    _F = lambda self, x, y, z: ((x & y) | (~x & z))
    _G = lambda self, x, y, z: ((x & y) | (x & z) | (y & z))
    _H = lambda self, x, y, z: (x ^ y ^ z)

    def __init__(self, message, ml=None, A=0x67452301, B=0xefcdab89, C=0x98badcfe, D=0x10325476):
        self.A, self.B, self.C, self.D = A, B, C, D

        if ml is None:
            ml = len(message) * 8

        length = pack('<Q', ml)

        while len(message) > 64:
            self._handle(message[:64])
            message = message[64:]

        message += b'\x80'
        message += bytes((56 - len(message) % 64) % 64)
        message += length

        while len(message):
            self._handle(message[:64])
            message = message[64:]

    def _handle(self, chunk):
        X = list(unpack('<' + 'I' * 16, chunk))
        A, B, C, D = self.A, self.B, self.C, self.D

        for i in range(16):
            k = i
            if i % 4 == 0:
                A = left_rotate((A + self._F(B, C, D) + X[k]) & 0xffffffff, 3)
            elif i % 4 == 1:
                D = left_rotate((D + self._F(A, B, C) + X[k]) & 0xffffffff, 7)
            elif i % 4 == 2:
                C = left_rotate((C + self._F(D, A, B) + X[k]) & 0xffffffff, 11)
            elif i % 4 == 3:
                B = left_rotate((B + self._F(C, D, A) + X[k]) & 0xffffffff, 19)

        for i in range(16):
            k = (i // 4) + (i % 4) * 4
            if i % 4 == 0:
                A = left_rotate((A + self._G(B, C, D) + X[k] + 0x5a827999) & 0xffffffff, 3)
            elif i % 4 == 1:
                D = left_rotate((D + self._G(A, B, C) + X[k] + 0x5a827999) & 0xffffffff, 5)
            elif i % 4 == 2:
                C = left_rotate((C + self._G(D, A, B) + X[k] + 0x5a827999) & 0xffffffff, 9)
            elif i % 4 == 3:
                B = left_rotate((B + self._G(C, D, A) + X[k] + 0x5a827999) & 0xffffffff, 13)

        order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(16):
            k = order[i]
            if i % 4 == 0:
                A = left_rotate((A + self._H(B, C, D) + X[k] + 0x6ed9eba1) & 0xffffffff, 3)
            elif i % 4 == 1:
                D = left_rotate((D + self._H(A, B, C) + X[k] + 0x6ed9eba1) & 0xffffffff, 9)
            elif i % 4 == 2:
                C = left_rotate((C + self._H(D, A, B) + X[k] + 0x6ed9eba1) & 0xffffffff, 11)
            elif i % 4 == 3:
                B = left_rotate((B + self._H(C, D, A) + X[k] + 0x6ed9eba1) & 0xffffffff, 15)

        self.A = (self.A + A) & 0xffffffff
        self.B = (self.B + B) & 0xffffffff
        self.C = (self.C + C) & 0xffffffff
        self.D = (self.D + D) & 0xffffffff

    def digest(self):
        return pack('<4I', self.A, self.B, self.C, self.D)

    def hex_digest(self):
        return hexlify(self.digest()).decode()


class Oracle:

    def __init__(self):
        # Choose a random word from the dictionary to use as key
        with open("/usr/share/dict/words") as dictionary:
            candidates = dictionary.readlines()
            self._key = candidates[randint(0, len(candidates) - 1)].rstrip().encode()

    def validate(self, message, digest):
        """Checks if the given digest matches the keyed MD4-mac of the given message."""
        return MD4(self._key + message).hex_digest() == digest

    def generate_digest(self, message):
        """Generates a MD4 MAC digest using the secret key."""
        return MD4(self._key + message).hex_digest()


def md_pad(message):
    """Pads the given message the same way the pre-processing of the MD4 algorithm does."""
    ml = len(message) * 8

    message += b'\x80'
    message += bytes((56 - len(message) % 64) % 64)
    message += pack('<Q', ml)

    return message


def length_extension_attack(message, original_digest, oracle):
    """Performs a length extension attack on the MD4 keyed MAC, forging a variant of the given
    message that ends with ";admin=true". Returns the new message and its valid MAC digest.
    """
    extra_payload = b';admin=true'

    # Try multiple key lengths
    for key_length in range(100):

        # Get the forged message (original-message || glue-padding || new-message)
        # The bytes of the key are not relevant in getting the glue padding, since we only
        # care about its length. Therefore we can use any key for the padding purposes.
        forged_message = md_pad(b'A' * key_length + message)[key_length:] + extra_payload

        # Get the MD4 internal state (h1, h2, h3, h4) by reversing the last step of the hash
        h = unpack('<4I', unhexlify(original_digest))

        # Compute the MD4 hash of the extra payload, by setting the state of the MD4 function to the
        # cloned one that we deduced from the original digest.
        # We also set the message length ml to be the total length of the message.
        forged_digest = MD4(extra_payload, (key_length + len(forged_message)) * 8, h[0], h[1], h[2], h[3]).hex_digest()

        # If the forged digest is valid, return it together with the forged message
        if oracle.validate(forged_message, forged_digest):
            return forged_message, forged_digest

    # Otherwise it means that we didn't guess correctly the key length
    raise Exception("It was not possible to forge the message: maybe the key was longer than 100 characters.")


def main():
    oracle = Oracle()

    # Compute the original digest of the given message
    message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    message_digest = oracle.generate_digest(message)

    # Forge a variant of this message and get its valid MAC
    forged_message, forged_digest = length_extension_attack(message, message_digest, oracle)

    # Check if the attack works properly
    assert b';admin=true' in forged_message
    assert oracle.validate(forged_message, forged_digest)


if __name__ == '__main__':
    main()
