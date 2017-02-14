from base64 import b64decode
from S2C10 import aes_ecb_encrypt
from S2C09 import pkcs7_unpad
from random import randint
from Crypto import Random
from S1C08 import count_aes_ecb_repetitions
from S2C12 import find_block_length, ECBOracle


class HarderECBOracle(ECBOracle):

    def __init__(self, secret_padding):
        super(HarderECBOracle, self).__init__(secret_padding)
        self._random_prefix = Random.new().read(randint(0, 255))

    def encrypt(self, data):
        """Encrypts with AES-128-ECB mode, after prepending a fixed (randomly-generated) string
        and appending a fixed (given) string to every plaintext.
        """
        return aes_ecb_encrypt(self._random_prefix + data + self._secret_padding, self._key)


def get_next_byte(prefix_length, block_length, curr_decrypted_message, encryption_oracle):
    """Finds the next byte of the mysterious message that the oracle
    is appending to our plaintext.
    """

    # Compute the number of characters that we want to use as input to have the first unknown
    # character of the mysterious message at the end of a block
    length_to_use = (block_length - prefix_length - (1 + len(curr_decrypted_message))) % block_length
    my_input = b'A' * length_to_use

    # Compute the number of bytes that we will take from the fake and from the real ciphertexts
    # to compare them. We will ignore everything is beyond the byte we are trying to discover.
    cracking_length = prefix_length + length_to_use + len(curr_decrypted_message) + 1

    # Compute the real ciphertext that the oracle would output with my input
    real_ciphertext = encryption_oracle.encrypt(my_input)

    # For each possible character
    for i in range(256):

        # Compute our fake ciphertext, trying to obtain the same as the real ciphertext
        fake_ciphertext = encryption_oracle.encrypt(my_input + curr_decrypted_message + bytes([i]))

        # If we found a character that, used in our fake input, let us obtain the same ciphertext
        if fake_ciphertext[:cracking_length] == real_ciphertext[:cracking_length]:

            # Return that character as the next byte of the message
            return bytes([i])

    # If there was no match (most likely due to padding), return empty byte
    return b''


def has_equal_block(ciphertext, block_length):
    """Checks if the given ciphertext contains two consecutive equal blocks"""
    for i in range(0, len(ciphertext) - 1, block_length):
        if ciphertext[i:i+block_length] == ciphertext[i+block_length:i+2*block_length]:
            return True

    return False


def find_prefix_length(encryption_oracle, block_length):
    """Finds the length of the randomly generated prefix that the encryption oracle
    adds to every plaintext before encrypting. First, the block where the prefix ends
    is searched; then the precise index where the prefix ends is searched.
    """

    # To find the index of the block where the prefix ends, we use the oracle to encrypt
    # an empty message and a 1 character message. Then we use them to find it as explained below.
    ciphertext1 = encryption_oracle.encrypt(b'')
    ciphertext2 = encryption_oracle.encrypt(b'a')

    # The first block where the two ciphertexts differ will be the block where the
    # prefix (which was the same for both the inputs) ended.
    prefix_length = 0
    for i in range(0, len(ciphertext2), block_length):
        if ciphertext1[i:i+block_length] != ciphertext2[i:i+block_length]:
            prefix_length = i
            break

    # Now, to find the precise index where the prefix ended, we will encrypt identical bytes,
    # in a number equal to two block_lengths, and we will increase this amount by an incremental
    # offset to see when those bytes will be shifted to be autonomous blocks (thus encrypted the same way)
    for i in range(block_length):
        fake_input = bytes([0] * (2 * block_length + i))
        ciphertext = encryption_oracle.encrypt(fake_input)

        # If the bytes have shifted enough, we can compute the precise index where the prefix ends
        # inside its last block, which is going to be equal to block_length - i
        if has_equal_block(ciphertext, block_length):
            return prefix_length + block_length - i if i != 0 else prefix_length

    raise Exception('The oracle is not using ECB')


def byte_at_a_time_ecb_decryption_harder(encryption_oracle):
    """Performs the byte-at-a-time ECB decryption attack to discover the secret padding used by the oracle."""

    # Find the block length
    block_length = find_block_length(encryption_oracle)

    # To detect if the oracle encrypts with ECB mode, we can encrypt a big enough (more
    # than three block sizes) plaintext of identical bytes. If the ciphertext presents
    # repeated blocks then we can deduct that it is very likely using ECB.
    ciphertext = encryption_oracle.encrypt(bytes([0] * 64))
    assert count_aes_ecb_repetitions(ciphertext) > 0

    # The number of bytes that we have to decrypt by breaking the encryption oracle
    # will be equal to the length of the ciphertext when we encrypt an empty message
    # subtracted by the length of the prefix (which we have to find).
    prefix_length = find_prefix_length(encryption_oracle, block_length)
    mysterious_text_length = len(encryption_oracle.encrypt(b'')) - prefix_length

    # At this point we have all the information that we need to crack the ECB
    # encryption oracle byte by byte.
    secret_padding = b''
    for i in range(mysterious_text_length):
        secret_padding += get_next_byte(prefix_length, block_length, secret_padding, encryption_oracle)

    # Return the complete padding as bytes
    return secret_padding


def main():
    """Approach:
    1) Find the block_length and the encryption mode (as in S2C12)
    2) Find the prefix length
    3) Decrypt byte-by-byte the mysterious message (similar to S2C12)
    """
    secret_padding = b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGF"
                               "pciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IH"
                               "RvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    oracle = HarderECBOracle(secret_padding)
    discovered_secret_padding = byte_at_a_time_ecb_decryption_harder(oracle)

    # Check if the attack works correctly
    assert pkcs7_unpad(discovered_secret_padding) == secret_padding


if __name__ == '__main__':
    main()
