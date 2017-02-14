from random import randint
from hashlib import sha256
from requests import post
from S5C36 import h, hmac_sha256


BASE_URL = "http://127.0.0.1:5000/"

# Generated using "openssl dhparam -text 1024".
N = int("008c5f8a80af99a7db03599f8dae8fb2f75b52501ef54a827b8a1a586f14dfb20d6b5e2ff878b9ad6bca0bb918d30431fca1770760aa4"
        "8be455cf5b949f3b86aa85a2573769e6c598f8d902cc1a0971a92e55b6e04c4d07e01ac1fa9bdefd1f04f95f197b000486c43917568ff"
        "58fafbffe12bde0c7e8f019fa1cb2b8e1bcb1f33", 16)

# Client and server agree on these values beforehand
g = 2
k = 3
I = 'ricpacca@crypto.com'
a = randint(0, N - 1)


def srp_zero_key():
    """Implements SRP zero key attack on the client side, which lets the user authenticate without password."""

    # The attack is performed with 3 different values of A
    for A in [0, N, N * 2]:

        # Client sets A to a hacking value
        response = post(BASE_URL, json={'I': I, 'A': A}).json()

        # Get the salt and B from the server
        salt = response.get('salt')
        B = response.get('B')

        # Generate u
        u = h(str(A) + str(B))

        # Do the hacker processing
        S_c = 0
        K_c = sha256(str(S_c).encode()).digest()

        # Compute the HMAC
        hm = hmac_sha256(K_c, salt.encode())

        response = post(BASE_URL, json={'hm': hm}).text
        yield response


def main():
    """NOTE: uses the same server as S5C36"""
    outcome = srp_zero_key()

    # Check that the attack works
    for response in outcome:
        assert response == "OK"


if __name__ == '__main__':
    main()
