from S2C10 import aes_ecb_encrypt, xor_data
from base64 import b64decode
from Crypto.Cipher import AES
import struct


def aes_ctr(data, key, nonce):
    """Encrypts or decrypts with AES-CTR mode."""
    output = b''
    counter = 0

    # Takes a block size of input at each time (or less if a block-size is not available), and XORs
    # it with the encrypted concatenation of nonce and counter.
    while data:

        # Get the little endian bytes concatenation of nonce and counter (each 64bit values)
        concatenated_nonce_and_counter = struct.pack('<QQ', nonce, counter)

        # Encrypt the concatenation of nonce and counter
        encrypted_counter = aes_ecb_encrypt(concatenated_nonce_and_counter, key)

        # XOR the encrypted value with the input data
        output += xor_data(encrypted_counter, data[:AES.block_size])

        # Update data to contain only the values that haven't been encrypted/decrypted yet
        data = data[AES.block_size:]

        # Update the counter as prescribed in the CTR mode of operation
        counter += 1

    return output


def main():

    # Check if the AES CTR encryption / decryption works correctly with the given example
    ciphertext = b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
    assert aes_ctr(ciphertext, b'YELLOW SUBMARINE', 0) == b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "

    # Check if it works also for a custom case
    message = b'Hey hello this is a test'
    key = b'A key of 8 bytes'
    nonce = 15
    assert aes_ctr(aes_ctr(message, key, nonce), key, nonce) == message


if __name__ == '__main__':
    main()
