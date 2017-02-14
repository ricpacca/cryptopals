from base64 import b64decode
from S2C10 import aes_ecb_encrypt
from S2C09 import pkcs7_unpad
from Crypto import Random
from Crypto.Cipher import AES
from S1C08 import count_aes_ecb_repetitions


class ECBOracle:
    """This oracle uses always the same key (generated during the initialization)."""

    def __init__(self, secret_padding):
        self._key = Random.new().read(AES.key_size[0])
        self._secret_padding = secret_padding

    def encrypt(self, data):
        """Encrypts with AES-128-ECB mode, after appending a fixed (given) string to every plaintext"""
        return aes_ecb_encrypt(data + self._secret_padding, self._key)


def find_block_length(encryption_oracle):
    """Returns the length of a block for the block cipher used by the encryption_oracle.
    To find the length of a block, we encrypt increasingly longer plaintexts until the size of the
    output ciphertext increases too. When this happens, we can then easily compute the length of a
    block as the difference between this new length of the ciphertext and its initial one.
    """
    my_text = b''
    ciphertext = encryption_oracle.encrypt(my_text)
    initial_len = len(ciphertext)
    new_len = initial_len

    while new_len == initial_len:
        my_text += b'A'
        ciphertext = encryption_oracle.encrypt(my_text)
        new_len = len(ciphertext)

    return new_len - initial_len


def get_next_byte(block_length, curr_decrypted_message, encryption_oracle):
    """Finds the next byte of the mysterious message that the oracle is appending to our plaintext."""

    # Compute the number of characters that we want to use as input to have the first unknown
    # character of the mysterious message at the end of a block
    length_to_use = (block_length - (1 + len(curr_decrypted_message))) % block_length
    prefix = b'A' * length_to_use

    # Compute the number of bytes that we will take from the fake and from the real ciphertexts
    # to compare them. We will ignore everything is beyond the byte we are trying to discover.
    cracking_length = length_to_use + len(curr_decrypted_message) + 1

    # Compute the real ciphertext that the oracle would output with the prefix we computed
    real_ciphertext = encryption_oracle.encrypt(prefix)

    # For each possible character
    for i in range(256):

        # Compute our fake ciphertext, trying to obtain the same as the real ciphertext
        fake_ciphertext = encryption_oracle.encrypt(prefix + curr_decrypted_message + bytes([i]))

        # If we found a character that, used in our fake input, let us obtain the same ciphertext
        if fake_ciphertext[:cracking_length] == real_ciphertext[:cracking_length]:

            # Return that character as the next byte of the message
            return bytes([i])

    # If there was no match (most likely due to padding), return empty byte
    return b''


def byte_at_a_time_ecb_decryption_simple(encryption_oracle):
    """Performs the byte-at-a-time ECB decryption attack to discover the secret padding used by the oracle."""

    # Find the block length
    block_length = find_block_length(encryption_oracle)

    # To detect if the oracle encrypts with ECB mode, we can encrypt a big enough (more
    # than three block sizes) plaintext of identical bytes. If the ciphertext presents
    # repeated blocks then we can deduct that it is very likely using ECB.
    ciphertext = encryption_oracle.encrypt(bytes([0] * 64))
    assert count_aes_ecb_repetitions(ciphertext) > 0

    # The number of bytes that we have to decrypt by breaking the encryption oracle
    # will be equal to the length of the ciphertext when we encrypt an empty message.
    mysterious_text_length = len(encryption_oracle.encrypt(b''))

    # At this point we have all the information that we need to crack the ECB
    # encryption oracle byte by byte.
    secret_padding = b''
    for i in range(mysterious_text_length):
        secret_padding += get_next_byte(block_length, secret_padding, encryption_oracle)

    # Return the complete padding as bytes
    return secret_padding


def main():
    """Approach:
    1) Find the block_length and the encryption mode
    2) Decrypt byte-by-byte the mysterious message
    """
    secret_padding = b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGF"
                               "pciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IH"
                               "RvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    oracle = ECBOracle(secret_padding)
    discovered_secret_padding = byte_at_a_time_ecb_decryption_simple(oracle)

    # Check if the attack works correctly
    assert pkcs7_unpad(discovered_secret_padding) == secret_padding


if __name__ == '__main__':
    main()
