from S2C10 import aes_cbc_decrypt
from S2C16 import find_block_length, find_prefix_length, Oracle
from S2C10 import xor_data


def check_ascii_compliance(plaintext):
    """Returns true if all the characters of plaintext are ASCII compliant (ie are in the ASCII table)."""
    return all(c < 128 for c in plaintext)


class LazyOracle(Oracle):
    """This oracle uses the key also as IV, which makes it insecure."""

    def __init__(self):
        super().__init__()
        self._iv = self._key    # Let's be lazy here

    def decrypt_and_check_admin(self, ciphertext):
        """Decrypts the ciphertext and: if the decrypted message is not ASCII compliant, raises an exception 
        and returns the bad plaintext; otherwise returns whether the characters ";admin=true;" are in the string.
        """
        plaintext = aes_cbc_decrypt(ciphertext, self._key, self._iv)

        if not check_ascii_compliance(plaintext):
            raise Exception("The message is not valid", plaintext)

        return b';admin=true;' in plaintext


def get_key_from_insecure_cbc(encryption_oracle):
    """Recovers the key from the lazy encryption oracle using the key also as iv.
    The approach used is the simple one outlined in the challenge description.
    """
    block_length = find_block_length(encryption_oracle.encrypt)
    prefix_length = find_prefix_length(encryption_oracle.encrypt, block_length)

    # Create three different blocks of plaintext and encrypt their concatenation
    p_1 = 'A' * block_length
    p_2 = 'B' * block_length
    p_3 = 'C' * block_length
    ciphertext = encryption_oracle.encrypt(p_1 + p_2 + p_3)

    # Force the ciphertext to be "C_1, 0, C_1"
    forced_ciphertext = ciphertext[prefix_length:prefix_length + block_length] + b'\x00' * block_length + \
                        ciphertext[prefix_length:prefix_length + block_length]

    # Expect an exception from the lazy oracle
    try:
        encryption_oracle.decrypt_and_check_admin(forced_ciphertext)
    except Exception as e:
        forced_plaintext = e.args[1]

        # Compute the key and return it
        # The first block of the plaintext will be equal to (decryption of c_1 XOR iv).
        # The last block of the plaintext will be equal to (decryption of c_1 XOR 0).
        # Therefore, to get the iv (which we know is equal to the key), we can just
        # xor the first and last blocks together.
        return xor_data(forced_plaintext[:block_length], forced_plaintext[-block_length:])

    raise Exception("Was not able to hack the key")


def main():
    encryption_oracle = LazyOracle()
    hacked_key = get_key_from_insecure_cbc(encryption_oracle)

    # Check that the key was recovered correctly
    assert encryption_oracle._key == hacked_key


if __name__ == '__main__':
    main()
