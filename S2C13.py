from S2C10 import aes_ecb_encrypt, aes_ecb_decrypt
from Crypto import Random
from Crypto.Cipher import AES


class ECBOracle:
    """This oracle uses the same key (randomly generated at initialization) every time."""

    def __init__(self):
        self._key = Random.new().read(AES.key_size[0])

    def encrypt(self, email):
        """Encrypts with AES-128-ECB the encoded user profile generated with the given email."""
        encoded = kv_encode(profile_for(email))
        bytes_to_encrypt = encoded.encode()
        return aes_ecb_encrypt(bytes_to_encrypt, self._key)

    def decrypt(self, ciphertext):
        """Decrypts the given ciphertext with the random key."""
        return aes_ecb_decrypt(ciphertext, self._key)


def kv_encode(dict_object):
    """Encodes a dictionary object to a string with the kv encoding format.

    For example, given this input:
    {
        foo: 'bar',
        baz: 'qux',
        zap: 'zazzle'
    }
    The function will return this string:
        foo=bar&baz=qux&zap=zazzle
    """
    encoded_text = ''
    for item in dict_object.items():
        encoded_text += item[0] + '=' + str(item[1]) + '&'

    # Return the encoded string without the last '&' character
    return encoded_text[:-1]


def kv_parse(encoded_text):
    """Decodes a kv encoded (see function above) string to a dictionary object"""
    output = {}
    attributes = encoded_text.split('&')

    # Add each attribute to the dictionary, converting it to int if it is a digit
    for attribute in attributes:
        values = attribute.split('=')
        key = int(values[0]) if values[0].isdigit() else values[0]
        value = int(values[1]) if values[1].isdigit() else values[1]
        output[key] = value

    return output


def profile_for(email):
    """Encodes a user profile in the kv encoding format, given an email address."""
    email = email.replace('&', '').replace('=', '')     # Remove special characters to avoid injection
    return {
        'email': email,
        'uid': 10,
        'role': 'user'
    }


def ecb_cut_and_paste(encryption_oracle):
    """By cutting and pasting pieces of ciphertexts, forces a ciphertext of an admin user"""

    # The first plaintext that will be encrypted is:
    # block 1:           block 2 (pkcs7 padded):                             and (omitting the padding):
    # email=xxxxxxxxxx   admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b   &uid=10&role=user
    prefix_len = AES.block_size - len("email=")
    suffix_len = AES.block_size - len("admin")
    email1 = 'x' * prefix_len + "admin" + (chr(suffix_len) * suffix_len)
    encrypted1 = encryption_oracle.encrypt(email1)

    # The second plaintext that will be encrypted is:
    # block 1:           block 2:           block 3
    # email=master@me.   com&uid=10&role=   user\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c
    email2 = "master@me.com"
    encrypted2 = encryption_oracle.encrypt(email2)

    # The forced ciphertext will cut and paste the previous ciphertexts to be decrypted as:
    # block 1:           block 2:           block 3:
    # email=master@me.   com&uid=10&role=   admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b
    forced = encrypted2[:32] + encrypted1[16:32]

    return forced


def main():
    """Approach: use ecb cut and paste technique"""
    oracle = ECBOracle()
    forced_ciphertext = ecb_cut_and_paste(oracle)

    # Check that the attack works properly
    decrypted = oracle.decrypt(forced_ciphertext)
    parsed = kv_parse(decrypted.decode())
    assert parsed['role'] == 'admin'


if __name__ == '__main__':
    main()
