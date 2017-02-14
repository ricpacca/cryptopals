from S3C18 import aes_ctr
from random import randint
from Crypto import Random
from Crypto.Cipher import AES
from S2C10 import xor_data


class Oracle:

    def __init__(self):
        self._key = Random.new().read(AES.key_size[0])
        self._nonce = randint(0, 2 ** 32 - 1)
        self._prefix = "comment1=cooking%20MCs;userdata="
        self._suffix = ";comment2=%20like%20a%20pound%20of%20bacon"

    def encrypt(self, data):
        """Adds the prefix and the suffix specified in the challenge and encrypts the data with AES-CTR"""
        data = data.decode().replace(';', '').replace('=', '')  # Remove special characters to avoid injection
        plaintext = (self._prefix + data + self._suffix).encode()
        return aes_ctr(plaintext, self._key, self._nonce)

    def decrypt_and_check_admin(self, ciphertext):
        """Decrypts the string and returns whether the characters ";admin=true;" are in the string"""
        data = aes_ctr(ciphertext, self._key, self._nonce)
        return b';admin=true;' in data


def get_prefix_length(oracle):
    """Finds the length of the prefix that mysterious_encrypt adds to the plaintext before encrypting."""
    # Encrypt two different ciphertexts
    ciphertext_a = oracle.encrypt(b'A')
    ciphertext_b = oracle.encrypt(b'B')

    # Since the stream ciphers encrypts bit by bit, the prefix length will be equal to
    # the number of bytes that are equal in the two ciphertext.
    prefix_length = 0
    while ciphertext_a[prefix_length] == ciphertext_b[prefix_length]:
        prefix_length += 1

    return prefix_length


def ctr_bit_flip(oracle):
    """Performs a stream cipher bit flipping attack to accomplish admin privileges in the decrypted data."""
    plaintext = b'?admin?true'
    ciphertext = oracle.encrypt(plaintext)

    # Prepare the data with which we want to XOR our goal ciphertext substring
    goal_text = b';admin=true'
    insert = xor_data(plaintext, goal_text)

    # Find the position where our goal ciphertext substring starts
    prefix_length = get_prefix_length(oracle)

    # Force our goal ciphertext block to be the encryption of our goal text
    forced_ciphertext = ciphertext[:prefix_length] + \
                        xor_data(ciphertext[prefix_length:prefix_length + len(plaintext)], insert) + \
                        ciphertext[prefix_length + len(plaintext):]

    return forced_ciphertext


def main():
    oracle = Oracle()
    forced_ciphertext = ctr_bit_flip(oracle)

    # Check if the ciphertext was forced properly
    assert oracle.decrypt_and_check_admin(forced_ciphertext)


if __name__ == "__main__":
    main()
