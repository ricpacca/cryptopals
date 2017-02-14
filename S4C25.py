from base64 import b64decode
from S1C07 import aes_ecb_decrypt
from S3C18 import aes_ctr
from Crypto import Random
from Crypto.Cipher import AES
from S2C10 import xor_data
import struct


class Oracle:

    def __init__(self):
        self._key = Random.new().read(AES.key_size[0])

    def edit(self, ciphertext, offset, new_text):
        """Changes the underlying plaintext of the given ciphertext at offset so that it
        contains new_text. Returns the new corresponding ciphertext.
        """

        # Get the indexes of the first and last block that will be affected by the change
        start_block = int(offset / AES.block_size)
        end_block = int((offset + len(new_text) - 1) / AES.block_size)

        # Find the keystream that would be used to encrypt the bytes in the affected blocks
        keystream = b''
        cipher = AES.new(self._key, AES.MODE_ECB)
        for block in range(start_block, end_block + 1):

            # Use the block number as counter (since we "know" that the counter starts from 0)
            # and set the nonce to 0 (we also "know" that).
            keystream += cipher.encrypt(struct.pack('<QQ', 0, block))

        # Find the precise bytes of the found keystream that would be used to encrypt new_text
        key_offset = offset % AES.block_size
        keystream = keystream[key_offset:key_offset + len(new_text)]

        # Encrypt new_text with the computed same-length keystream
        insert = xor_data(new_text, keystream)

        # Insert the new encrypted chunk in the ciphertext overwriting the underlying bytes at offset
        return ciphertext[:offset] + insert + ciphertext[offset + len(insert):]

    def encrypt(self, plaintext):
        """Encrypts the given plaintext with AES-CTR with a nonce of 0."""
        return aes_ctr(plaintext, self._key, 0)


def break_random_access_read_write_aes_ctr(ciphertext, encryption_oracle):
    """If the attacker has access to the edit() function to write on the ciphertext,
    then it is easy to decrypt the underlying plaintext:

    Since we know that the edit() function will encrypt the new_text that we give it
    with the same keystream used in the original ciphertext (shifted by offset), we can
    simply set the offset to zero and then overwrite the underlying plaintext of our ciphertext
    to be the ciphertext itself. Because by encrypting the ciphertext again we will basically
    decrypt it (that's how AES CTR works), the edit will return to us the original plaintext!
    """

    # Assume random key is still unknown, the attacker can control only offset and new_text
    # (given the ciphertext).
    return encryption_oracle.edit(ciphertext, 0, ciphertext)


def main():
    with open("S1C07_input.txt") as input_file:
        binary_data = b64decode(input_file.read())

    plaintext = aes_ecb_decrypt(binary_data, b'YELLOW SUBMARINE')
    oracle = Oracle()

    # Compute the ciphertext and give it to the attacker
    ciphertext = oracle.encrypt(plaintext)
    cracked_plaintext = break_random_access_read_write_aes_ctr(ciphertext, oracle)

    # Check if the attack worked
    assert plaintext == cracked_plaintext
    print(cracked_plaintext.decode().rstrip())


if __name__ == "__main__":
    main()
