from S5C39 import RSA, mod_inv, int_to_bytes


def find_cube_root(n):
    """Finds the cube root of n using binary search."""
    lo = 0
    hi = n

    while lo < hi:
        mid = (lo + hi) // 2
        if mid**3 < n:
            lo = mid + 1
        else:
            hi = mid

    return lo


def rsa_broadcast_attack(ciphertexts):
    """Uses the Chinese Remainder Theorem (CRT) to break e=3 RSA given three ciphertexts of the same plaintext.
    This attack could be easily coded to work also when a different number of ciphertexts is provided.
    Check here for reference: https://crypto.stanford.edu/pbc/notes/numbertheory/crt.html
    """
    c0, c1, c2 = ciphertexts[0][0], ciphertexts[1][0], ciphertexts[2][0]
    n0, n1, n2 = ciphertexts[0][1], ciphertexts[1][1], ciphertexts[2][1]
    m0, m1, m2 = n1 * n2, n0 * n2, n0 * n1

    t0 = (c0 * m0 * mod_inv(m0, n0))
    t1 = (c1 * m1 * mod_inv(m1, n1))
    t2 = (c2 * m2 * mod_inv(m2, n2))
    c = (t0 + t1 + t2) % (n0 * n1 * n2)

    return int_to_bytes(find_cube_root(c))


def main():
    plaintext = b"Hello, I'm a Javascript programmer."

    ciphertexts = []
    for _ in range(3):
        rsa = RSA(1024)
        ciphertexts.append((rsa.encrypt(plaintext), rsa.n))

    assert rsa_broadcast_attack(ciphertexts) == plaintext


if __name__ == '__main__':
    main()
