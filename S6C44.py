import re
from itertools import combinations
from S6C43 import sha1, DSA, mod_inv, get_x_from_k


def parse_signature_file():
    """Parses the input file and returns an array containing (s, r, m) of each signature."""
    pattern = r'msg: [a-zA-Z.,\' ]+\n' \
              r's: ([0-9]+)\n' \
              r'r: ([0-9]+)\n' \
              r'm: ([0-9a-f]+)\n?'

    f = open('S6C44_input.txt')
    s = f.read()
    f.close()

    return re.findall(pattern, s)


def nonce_recovery_from_repeated_nonce():
    """Finds two messages signed with the same nonce k, recovers that nonce k and, from k, gets the private key x."""

    # Parse the file with the signatures
    signatures = parse_signature_file()

    # Find two pairs of signatures that used the same k
    # This is easy to find, because when the same k is used r will be the same, since r
    # depends only on (g, p, q and k), and (g, p, q) are fixed in our implementation.
    pairs = combinations(signatures, 2)
    for (x, y) in pairs:
        r1, r2 = int(x[1]), int(y[1])

        # Check if this pair is one of those which used the same k
        if r1 != r2:
            continue

        s1, s2 = int(x[0]), int(y[0])
        m1, m2 = int(x[2], 16), int(y[2], 16)

        # 9th grade math to find k (it's a simple system of linear equations)
        k = (((m1 - m2) % DSA.DEFAULT_Q) * mod_inv((s1 - s2) % DSA.DEFAULT_Q, DSA.DEFAULT_Q)) % DSA.DEFAULT_Q
        return get_x_from_k(DSA.DEFAULT_Q, k, r1, s1, m1)


def main():
    y = int("2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8"
            "5519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430"
            "f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821", 16)

    # Hack the key and from signatures which used a repeated nonce
    hacked_x = nonce_recovery_from_repeated_nonce()
    c = hex(hacked_x)[2:].encode()

    # Check that the private key that we recovered is the correct one
    assert sha1(c) == "ca8f6f7c66fa362d40760d135b763eb8527d3d52"
    assert pow(DSA.DEFAULT_G, hacked_x, DSA.DEFAULT_P) == y


if __name__ == '__main__':
    main()
