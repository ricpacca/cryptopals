from binascii import hexlify


def repeating_key_xor(plaintext, key):
    """Implements the repeating-key XOR encryption."""
    ciphertext = b''
    i = 0

    for byte in plaintext:
        ciphertext += bytes([byte ^ key[i]])

        # Cycle i to point to the next byte of the key
        i = i + 1 if i < len(key) - 1 else 0

    return ciphertext


def main():
    c = repeating_key_xor(b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", b'ICE')

    # Check that the encryption works properly
    assert (str(hexlify(c), "utf-8") == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622632427276527"
                                        "2a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")


if __name__ == "__main__":
    main()
