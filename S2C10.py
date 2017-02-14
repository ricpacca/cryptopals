from base64 import b64decode
from Crypto.Cipher import AES
from S2C09 import pkcs7_pad, pkcs7_unpad
from S1C07 import aes_ecb_decrypt


def aes_ecb_encrypt(data, key):
    """Encrypts the given data with AES-ECB, using the given key.
    The data is always PKCS 7 padded before being encrypted.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pkcs7_pad(data, AES.block_size))


def xor_data(binary_data_1, binary_data_2):
    """Returns the xor of the two binary arrays given."""
    return bytes([b1 ^ b2 for b1, b2 in zip(binary_data_1, binary_data_2)])


def aes_cbc_encrypt(data, key, iv):
    """Encrypts the given data with AES-CBC, using the given key and iv."""
    ciphertext = b''
    prev = iv

    # Process the encryption block by block
    for i in range(0, len(data), AES.block_size):

        # Always PKCS 7 pad the current plaintext block before proceeding
        curr_plaintext_block = pkcs7_pad(data[i:i + AES.block_size], AES.block_size)
        block_cipher_input = xor_data(curr_plaintext_block, prev)
        encrypted_block = aes_ecb_encrypt(block_cipher_input, key)
        ciphertext += encrypted_block
        prev = encrypted_block

    return ciphertext


def aes_cbc_decrypt(data, key, iv, unpad=True):
    """Decrypts the given AES-CBC encrypted data with the given key and iv.
    Returns the unpadded decrypted message when unpad is true, or keeps the plaintext
    padded when unpad is false.
    """
    plaintext = b''
    prev = iv

    # Process the decryption block by block
    for i in range(0, len(data), AES.block_size):
        curr_ciphertext_block = data[i:i + AES.block_size]
        decrypted_block = aes_ecb_decrypt(curr_ciphertext_block, key)
        plaintext += xor_data(prev, decrypted_block)
        prev = curr_ciphertext_block

    # Return the plaintext either unpadded or left with the padding depending on the unpad flag
    return pkcs7_unpad(plaintext) if unpad else plaintext


def main():
    iv = b'\x00' * AES.block_size
    key = b'YELLOW SUBMARINE'
    with open("S2C10_input.txt") as input_file:
        binary_data = b64decode(input_file.read())

    # Compute and print the decrypted plaintext with the given input
    print(aes_cbc_decrypt(binary_data, key, iv).decode().rstrip())

    # Check that the encryption/decryption methods work fine with a custom input
    custom_input = b'Trying to decrypt something else to see if it works.'
    assert aes_cbc_decrypt(aes_cbc_encrypt(custom_input, key, iv), key, iv) == custom_input

if __name__ == '__main__':
    main()
