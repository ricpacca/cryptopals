from S3C21 import MT19937
from random import randint
from Crypto import Random
from S2C10 import xor_data
import struct


class MT19937Cipher:

    def __init__(self, key):
        self._rng = MT19937(key)

    def encrypt(self, plaintext):
        """Uses the MT19937 PRNG to generate a keystream of enough bytes (at least as long as the
        text we want to encrypt/decrypt), and then XORs it with the input text.
        """
        keystream = b''

        # We use all the bits of the PRNG outputs (there is no need take just 16 bits per output)
        while len(keystream) < len(plaintext):
            keystream += struct.pack('>L', self._rng.extract_number())

        return xor_data(plaintext, keystream)

    def decrypt(self, ciphertext):
        """Decryption works the same as encryption."""
        return self.encrypt(ciphertext)


def find_mt19937_stream_cipher_key(ciphertext, known_plaintext):
    """Brute-force all possible 16-bit seeds (used as a key for the MT19937 stream cipher) until the
    ciphertext decrypts to a message containing our username (which is a known part of the plaintext).
    """
    print("> Brute-forcing all possible seeds...")

    for guessed_seed in range(2**16):
        candidate = MT19937Cipher(guessed_seed).decrypt(ciphertext)

        if known_plaintext in candidate:
            print("> Seed found:", guessed_seed)
            return guessed_seed

    # If after trying all the possible 16-bit seeds we still haven't
    # found the right one, it means that it was not a 16-bit number.
    raise Exception("The seed was not a 16 bit number")


def main():
    # Generate a random seed, which we'll use as a key
    seed = randint(0, 2 ** 16 - 1)

    # Generate the plaintext which will be encrypted to get the password token
    random_prefix = Random.new().read(randint(0, 100)) + b';'  # Small to make the cracking just slightly faster
    known_plaintext = b'ricpacca'                       # Username of someone willing to reset his password
    random_suffix = b';' + b'password_reset=true'       # Let's make it more realistic

    ciphertext = MT19937Cipher(seed).encrypt(random_prefix + known_plaintext + random_suffix)
    guessed_seed = find_mt19937_stream_cipher_key(ciphertext, known_plaintext)

    # Check that the attack worked and print the recovered plaintext
    assert guessed_seed == seed
    print("> Decrypted password reset plaintext:", MT19937Cipher(seed).encrypt(ciphertext))


if __name__ == '__main__':
    main()
