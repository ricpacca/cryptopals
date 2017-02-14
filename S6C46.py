from base64 import b64decode
from S5C39 import int_to_bytes, RSA
from math import ceil, log
from decimal import *


class RSAParityOracle(RSA):
    """Extends the RSA class by adding a method to verify the parity of data."""

    def is_parity_odd(self, encrypted_int_data):
        """Decrypts the input data and returns whether the resulting number is odd."""
        return pow(encrypted_int_data, self._d, self.n) & 1


def parity_oracle_attack(ciphertext, rsa_parity_oracle, holliwood=False):
    """Decrypts the given ciphertext using just the parity method of the oracle. Here a detailed explanation:
    http://secgroup.dais.unive.it/wp-content/uploads/2012/11/Practical-Padding-Oracle-Attacks-on-RSA.html
    """

    # Compute the encryption of 2, which will be our ciphertext multiplier
    multiplier = pow(2, rsa_parity_oracle.e, rsa_parity_oracle.n)

    # Initialize lower and upper bound.
    # I need to use Decimal because it allows me to set the precision for the floating point
    # numbers, which we will need when doing the binary search divisions.
    lower_bound = Decimal(0)
    upper_bound = Decimal(rsa_parity_oracle.n)

    # Compute the number of iterations that we have to do
    k = int(ceil(log(rsa_parity_oracle.n, 2)))

    # Set the precision of the floating point number to be enough
    getcontext().prec = k

    # Binary search for the correct plaintext
    for _ in range(k):
        ciphertext = (ciphertext * multiplier) % rsa_parity_oracle.n

        if rsa_parity_oracle.is_parity_odd(ciphertext):
            lower_bound = (lower_bound + upper_bound) / 2
        else:
            upper_bound = (lower_bound + upper_bound) / 2

        # If the user wants to see the message being decrypted at every iteration, print the current upper_bound
        if holliwood is True:
            print(int_to_bytes(int(upper_bound)))

    # Return the binary version of the upper_bound (converted from Decimal to int)
    return int_to_bytes(int(upper_bound))


def main():
    input_bytes = b64decode("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IG"
                            "Fyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==")

    rsa_parity_oracle = RSAParityOracle(1024)

    ciphertext = rsa_parity_oracle.encrypt(input_bytes)
    rsa_parity_oracle.decrypt(ciphertext)

    # Check if the attack works
    plaintext = parity_oracle_attack(ciphertext, rsa_parity_oracle)
    assert plaintext == input_bytes


if __name__ == '__main__':
    main()
