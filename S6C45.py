from S6C43 import DSA, mod_inv


def dsa_parameter_tempering():
    """Makes sure that with a proper DSA parameter tampering we can generate valid signatures for any message."""

    # I will skip the g = 1 tampering because my DSA implementation does not allow r = 0 anyway
    # Let's go directly to the g = p + 1
    dsa = DSA(g=DSA.DEFAULT_P + 1)

    # Test that a legit signature works properly
    some_text = b"Let's see what happens when I sign this message with (g = p + 1) DSA"
    legit_signature = dsa.sign(some_text)
    assert dsa.verify(some_text, legit_signature[0], legit_signature[1])

    # Create a forged signature
    z = 2
    forged_r = pow(dsa.y, z, DSA.DEFAULT_P) % DSA.DEFAULT_Q
    forged_s = (forged_r * mod_inv(z, dsa.DEFAULT_Q)) % dsa.DEFAULT_Q

    # Test that a forged signature works properly
    assert dsa.verify(b'Hello, world', forged_r, forged_s)
    assert dsa.verify(b'Goodbye, world', forged_r, forged_s)


def main():
    dsa_parameter_tempering()


if __name__ == '__main__':
    main()
