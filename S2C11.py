from S1C08 import count_aes_ecb_repetitions
from S2C10 import aes_ecb_encrypt, aes_cbc_encrypt
from random import randint
from Crypto.Cipher.AES import block_size
from Crypto import Random


class AesEncryptionOracle:
    """Oracle which encrypts the given data using every time a random AES method (chosen between ECB and CBC),
    a random key, a random iv (in case of CBC) and also adds a random padding before and after the plaintext.
    """

    @staticmethod
    def encrypt(plaintext):
        # Add a random padding before and after the plaintext
        padded_plaintext = AesEncryptionOracle._pad_with_bytes(plaintext)

        # Generate a random key
        key = Random.new().read(block_size)

        # Encrypt randomly with ECB or CBC
        if randint(0, 1) == 0:
            return "ECB", aes_ecb_encrypt(padded_plaintext, key)
        else:
            return "CBC", aes_cbc_encrypt(padded_plaintext, key, Random.new().read(block_size))

    @staticmethod
    def _pad_with_bytes(binary_data):
        """Returns the given binary_data with a padded with a short random prefix and suffix."""
        return Random.new().read(randint(5, 10)) + binary_data + Random.new().read(randint(5, 10))


def detect_cipher(ciphertext):
    """Detects if the given ciphertext was encrypted with ECB or CBC mode."""

    # When there are some repeated chunks in the ciphertext, it is most likely becaues
    # it wes encrypted with ECB
    if count_aes_ecb_repetitions(ciphertext) > 0:
        return "ECB"
    else:
        return "CBC"


def main():
    oracle = AesEncryptionOracle()

    # We choose a repeating input data so that we will be able to detect
    # repetitions in the ciphertext (if it's encrypted with ECB) later.
    input_data = bytes([0]*64)

    # Check that the detection method works correctly
    for _ in range(1000):
        encryption_used, ciphertext = oracle.encrypt(input_data)
        encryption_detected = detect_cipher(ciphertext)
        assert encryption_used == encryption_detected


if __name__ == '__main__':
    main()
