from random import randint
from S5C39 import int_to_bytes, RSA
from Crypto import Random


def ceil(a, b):
    return (a + b - 1) // b


class RSAPaddingOracle(RSA):
    """Extends the RSA class by making the decryption PKCS 1.5 compliant and by adding a method
    to verify the padding of data."""

    def is_padding_correct(self, encrypted_int_data):
        """Decrypts the input data and returns whether its padding is correct according to PKCS 1.5.
        NOTE: It is super important (I spent hours to debug this), that this method also checks
        the length of the decrypted plaintext, and not only the starting bytes.
        """
        plaintext = self.decrypt(encrypted_int_data)
        return len(plaintext) == ceil(self.n.bit_length(), 8) and plaintext[:2] == b'\x00\x02'

    def decrypt(self, encrypted_int_data):
        """Decrypts the data and prepends 0 (the first byte of the PKCS 1.5 format) to it."""
        return b'\x00' + super(RSAPaddingOracle, self).decrypt(encrypted_int_data)


def append_and_merge(intervals, lower_bound, upper_bound):
    """Adds a new interval to the list of intervals. In particular:
    If there is no interval overlapping with the given boundaries, it just appends the new interval to the list.
    If there is already an interval overlapping with the given boundaries, it merges the two intervals together.
    """

    # Check if there exist an interval which is overlapping with the lower_bound and
    # upper_bound of the new interval we want to append
    for i, (a, b) in enumerate(intervals):

        # If there is an overlap, then replace the boundaries of the overlapping
        # interval with the wider (or equal) boundaries of the new merged interval
        if not (b < lower_bound or a > upper_bound):
            new_a = min(lower_bound, a)
            new_b = max(upper_bound, b)
            intervals[i] = new_a, new_b
            return

    # If there was no interval overlapping with the one we want to add, add
    # the new interval as a standalone interval to the list
    intervals.append((lower_bound, upper_bound))


def pkcs_1_5_padding_oracle_attack(ciphertext, rsa_padding_oracle, key_byte_length, c_is_pkcs_conforming=True):
    """Implements the PKCS 1.5 padding oracle attack described by Bleichenbacher in CRYPTO '98."""

    # For convenience, let:
    B = 2 ** (8 * (key_byte_length - 2))
    n, e = rsa_padding_oracle.n, rsa_padding_oracle.e

    # Set the starting values
    c_0 = ciphertext
    M = [(2 * B, 3 * B - 1)]
    i = 1

    # If c is not already PKCS 1.5 conforming, perform an additional step
    if not c_is_pkcs_conforming:

        # Step 1: Blinding
        while True:
            s = randint(0, n - 1)
            c_0 = (ciphertext * pow(s, e, n)) % n
            if rsa_padding_oracle.is_padding_correct(c_0):
                break

    # Find the decrypted message through several iterations
    while True:

        # Step 2.a: Starting the search
        if i == 1:
            s = ceil(rsa_padding_oracle.n, 3 * B)
            while True:

                c = (c_0 * pow(s, e, n)) % n
                if rsa_padding_oracle.is_padding_correct(c):
                    break

                s += 1

        # Step 2.b: Searching with more than one interval left
        elif len(M) >= 2:
            while True:
                s += 1
                c = (c_0 * pow(s, e, n)) % n

                if rsa_padding_oracle.is_padding_correct(c):
                    break

        # Step 2.c: Searching with one interval left
        elif len(M) == 1:
            a, b = M[0]

            # Check if the interval contains the solution
            if a == b:

                # And if it does, return it as bytes
                return b'\x00' + int_to_bytes(a)

            r = ceil(2 * (b * s - 2 * B), n)
            s = ceil(2 * B + r * n, b)

            while True:
                c = (c_0 * pow(s, e, n)) % n
                if rsa_padding_oracle.is_padding_correct(c):
                    break

                s += 1
                if s > (3 * B + r * n) // a:
                    r += 1
                    s = ceil((2 * B + r * n), b)

        # Step 3: Narrowing the set of solutions
        M_new = []

        for a, b in M:
            min_r = ceil(a * s - 3 * B + 1, n)
            max_r = (b * s - 2 * B) // n

            for r in range(min_r, max_r + 1):
                l = max(a, ceil(2 * B + r * n, s))
                u = min(b, (3 * B - 1 + r * n) // s)

                if l > u:
                    raise Exception('Unexpected error: l > u in step 3')

                append_and_merge(M_new, l, u)

        if len(M_new) == 0:
            raise Exception('Unexpected error: there are 0 intervals.')

        M = M_new
        i += 1


def pkcs_1_5_pad(binary_data, key_byte_length):
    """Pads the given binary data conforming to the PKCS 1.5 format."""
    padding_string = Random.new().read(key_byte_length - 3 - len(binary_data))
    return b'\x00\x02' + padding_string + b'\x00' + binary_data


def main():
    key_bit_length = 256
    key_byte_length = ceil(key_bit_length, 8)

    rsa_padding_oracle = RSAPaddingOracle(key_bit_length)

    # Pad a short message m and encrypt it to get c
    data_block = b'kick it, CC'
    m = pkcs_1_5_pad(data_block, key_byte_length)

    c = rsa_padding_oracle.encrypt(m)

    # Check that the rsa padding oracle decrypts the c correctly
    assert rsa_padding_oracle.is_padding_correct(c)

    # Test that the attack works
    hacked_message = pkcs_1_5_padding_oracle_attack(c, rsa_padding_oracle, key_byte_length)
    assert m == hacked_message


if __name__ == '__main__':
    main()
