import re
from S4C28 import sha1
from binascii import unhexlify
from S5C40 import find_cube_root
from S5C39 import int_to_bytes, RSA


# 15-byte ASN.1 value for SHA1 (from rfc 3447)
ASN1_SHA1 = b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'


class RSADigitalSignature(RSA):
    """Extends the RSA class coded before with the sign / verify functions."""

    def sign(self, message):
        return self.decrypt(int.from_bytes(message, byteorder='big'))

    def verify(self, encrypted_signature, message):

        # Decrypt the given encrypted signature
        signature = b'\x00' + int_to_bytes(self.encrypt(encrypted_signature))

        # Verify that the signature contains a block in PKCS1.5 standard format (vulnerable implementation)
        r = re.compile(b'\x00\x01\xff+?\x00.{15}(.{20})', re.DOTALL)
        m = r.match(signature)
        if not m:
            return False

        # Take the hash part of the signature and compare with the server-computed hash
        hashed = m.group(1)
        return hashed == unhexlify(sha1(message))


def forge_signature(message, key_length):
    """Forges a valid RSA signature for the given message using the Bleichenbacher's e=3 RSA Attack."""

    # Prepare the block which will look like PKCS1.5 standard format to the vulnerable server
    block = b'\x00\x01\xff\x00' + ASN1_SHA1 + unhexlify(sha1(message))
    garbage = (((key_length + 7) // 8) - len(block)) * b'\x00'
    block += garbage

    # Get the int version of the block and find its cube root (emulating the signing process)
    pre_encryption = int.from_bytes(block, byteorder='big')
    forged_sig = find_cube_root(pre_encryption)

    # Convert the signature to bytes and return it
    return int_to_bytes(forged_sig)


def main():
    message = b'hi mom'
    forged_signature = forge_signature(message, 1024)

    assert RSADigitalSignature(1024).verify(forged_signature, message)


if __name__ == '__main__':
    main()
