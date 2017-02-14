import struct
from random import randint
from binascii import unhexlify
from S4C28 import sha1, sha1_mac


class Oracle:

    def __init__(self):
        # Choose a random word from the dictionary to use as key
        with open("/usr/share/dict/words") as dictionary:
            candidates = dictionary.readlines()
            self._key = candidates[randint(0, len(candidates) - 1)].rstrip().encode()

    def validate(self, message, digest):
        """Checks if the given digest matches the keyed SHA1-mac of the given message."""
        return sha1_mac(self._key, message) == digest

    def generate_digest(self, message):
        """Generates a SHA1 MAC digest using the secret key."""
        return sha1_mac(self._key, message)


def md_pad(message):
    """Pads the given message the same way the pre-processing of the SHA1 algorithm does."""
    ml = len(message) * 8
    message += b'\x80'
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'

    message += struct.pack('>Q', ml)
    return message


def length_extension_attack(message, original_digest, oracle):
    """Performs a length extension attack on the SHA1 keyed MAC, forging a variant of the given
    message that ends with ";admin=true". Returns the new message and its valid MAC digest.
    """
    extra_payload = b';admin=true'

    # Try multiple key lengths
    for key_length in range(100):

        # Get the forged message (original-message || glue-padding || new-message)
        # The bytes of the key are not relevant in getting the glue padding, since we only
        # care about its length. Therefore we can use any key for the padding purposes.
        forged_message = md_pad(b'A' * key_length + message)[key_length:] + extra_payload

        # Get the SHA1 internal state (h1, h2, h3, h4, h5) by reversing the last step of the hash
        h = struct.unpack('>5I', unhexlify(original_digest))

        # Compute the SHA1 hash of the extra payload, by setting the state of the SHA1 function to the
        # cloned one that we deduced from the original digest.
        # We also set the message length ml to be the total length of the message.
        forged_digest = sha1(extra_payload, (key_length + len(forged_message)) * 8, h[0], h[1], h[2], h[3], h[4])

        # If the forged digest is valid, return it together with the forged message
        if oracle.validate(forged_message, forged_digest):
            return forged_message, forged_digest

    # Otherwise it means that we didn't guess correctly the key length
    raise Exception("It was not possible to forge the message: maybe the key was longer than 100 characters.")


def main():
    oracle = Oracle()

    # Compute the original digest of the given message
    message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    message_digest = oracle.generate_digest(message)

    # Forge a variant of this message and get its valid MAC
    forged_message, forged_digest = length_extension_attack(message, message_digest, oracle)

    # Check if the attack works properly
    assert b';admin=true' in forged_message
    assert oracle.validate(forged_message, forged_digest)


if __name__ == '__main__':
    main()
