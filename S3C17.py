from S2C09 import is_pkcs7_padded, pkcs7_unpad
from S2C10 import aes_cbc_encrypt, aes_cbc_decrypt
from random import randint
from Crypto import Random
from Crypto.Cipher.AES import block_size, key_size
from base64 import b64decode


class Oracle:

    def __init__(self, possible_inputs):
        self.iv = Random.new().read(block_size)
        self._key = Random.new().read(key_size[0])
        self._possible_inputs = possible_inputs

    def get_encrypted_message(self):
        """Selects at random one of the 10 input strings and encrypts it under a random key and IV with AES-128-CBC."""
        chosen_input = self._possible_inputs[randint(0, len(self._possible_inputs) - 1)].encode()
        return aes_cbc_encrypt(chosen_input, self._key, self.iv)

    def decrypt_and_check_padding(self, ciphertext, iv):
        """Decrypts the given ciphertext with the given IV and with the random key generated before
        by the encryption oracle. Returns True if the decrypted plaintext is pkcs7 padded correctly.
        """
        plaintext = aes_cbc_decrypt(ciphertext, self._key, iv, False)
        return is_pkcs7_padded(plaintext)


def create_forced_previous_block(iv, guessed_byte, padding_len, found_plaintext):
    """Creates a forced block of the ciphertext, ideally to be given as IV to decrypt the following block.
    The forced IV will be used for the attack on the padding oracle CBC encryption.
    """

    # Get the index of the first character of the padding
    index_of_forced_char = len(iv) - padding_len

    # Using the guessed byte given as input, try to force the first character of the
    # padding to be equal to the length of the padding itself
    forced_character = iv[index_of_forced_char] ^ guessed_byte ^ padding_len

    # Form the forced ciphertext by adding to it the forced character...
    output = iv[:index_of_forced_char] + bytes([forced_character])

    # ...and the characters that were forced before (for which we already know the plaintext)
    m = 0
    for k in range(block_size - padding_len + 1, block_size):

        # Force each of the following characters of the IV so that the matching characters in
        # the following block will be decrypted to "padding_len"
        forced_character = iv[k] ^ found_plaintext[m] ^ padding_len
        output += bytes([forced_character])
        m += 1

    return output


def attack_padding_oracle(ciphertext, oracle):
    """Decrypts the given ciphertext by using the padding oracle CBC encryption attack."""
    plaintext = b''

    # Split the ciphertext in blocks of the AES block_size (which can get it from the IV too)
    ciphertext_blocks = [oracle.iv] + [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]

    for c in range(1, len(ciphertext_blocks)):
        plaintext_block = b''   # This is the part of plaintext corresponding to each ciphertext block

        # Take each character of the ciphertext block (starting from the last one)
        # and decrypt it by forcing the previous block as IV.
        for i in range(block_size - 1, -1, -1):

            # The padding len for the current character will depend on how many characters of this
            # block (starting from the right), we have already decrypted.
            padding_len = len(plaintext_block) + 1

            # Find each possible character which gives us a correct padding
            possible_last_bytes = []
            for j in range(256):

                # Create a IV with the guessed character j
                forced_iv = create_forced_previous_block(ciphertext_blocks[c - 1], j, padding_len, plaintext_block)

                # If the guessed character j gave us a working padding, save it as one of the candidates
                if oracle.decrypt_and_check_padding(ciphertext_blocks[c], forced_iv) is True:
                    possible_last_bytes += bytes([j])

            # In case of ambiguity, if we found more than one candidate, we can choose the best by trying
            # to force the next character too.
            #
            # This is useful because, for example, if we were trying to find the last character
            # of this plaintext (which was already padded):
            #
            #     123456789012/x04/x04/x04/x04
            #
            # There would be two possible last characters that form a valid padding (/x01 and /x04).
            # However if we try the next character too, we can easily choose the correct one.
            if len(possible_last_bytes) != 1:
                for byte in possible_last_bytes:
                    for j in range(256):
                        forced_iv = create_forced_previous_block(ciphertext_blocks[c - 1], j, padding_len + 1,
                                                                 bytes([byte]) + plaintext_block)

                        # If we manage to get a valid padding, then it's very likely that this
                        # candidate is the one that we want. So exclude the others and exit the loop.
                        if oracle.decrypt_and_check_padding(ciphertext_blocks[c], forced_iv) is True:
                            possible_last_bytes = [byte]
                            break

            # Got the new byte of the plaintext corresponding to the block we are decrypting,
            # add it on top of the decrypted text.
            plaintext_block = bytes([possible_last_bytes[0]]) + plaintext_block

        # Add the block we have decrypted to the final plaintext
        plaintext += plaintext_block

    # Return the unpadded plaintext bytes (in base 64)
    return pkcs7_unpad(plaintext)


def main():
    with open("S3C17_input.txt") as f:
        strings = f.read().splitlines()

    oracle = Oracle(strings)
    result = attack_padding_oracle(oracle.get_encrypted_message(), oracle)

    # Print the decryption of the message that was chosen. If it's human readable then the attack worked.
    # The numbers at the beginning are normal and they are present in every ciphertext of the input file
    print(b64decode(result.decode()))


if __name__ == '__main__':
    main()
