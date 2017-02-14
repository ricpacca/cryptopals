from S5C33 import modular_pow
from S5C36 import hmac_sha256, h
from flask import Flask, request, jsonify
from hashlib import sha256
from random import randint


# Generated using "openssl dhparam -text 1024".
N = int("008c5f8a80af99a7db03599f8dae8fb2f75b52501ef54a827b8a1a586f14dfb20d6b5e2ff878b9ad6bca0bb9"
        "18d30431fca1770760aa48be455cf5b949f3b86aa85a2573769e6c598f8d902cc1a0971a92e55b6e04c4d07e"
        "01ac1fa9bdefd1f04f95f197b000486c43917568ff58fafbffe12bde0c7e8f019fa1cb2b8e1bcb1f33", 16)

# Client and server agree on these values beforehand
g = 2
k = 3

# Password database
passwords = {'ricpacca@crypto.com': "PaS$w0rd"}

# Server computes these values on his own
b = randint(0, N - 1)
salt = str(randint(0, 2**32 - 1))

# Values to update later
v = None
A, B = None, None
S, K = None, None

app = Flask(__name__)


@app.route('/', methods=['POST'])
def login():
    global v, A, B, S, K

    # This example server supports only HTTP POST requests
    if request.method == 'POST':

        # Get the data sent by the client as json
        post_data = request.get_json()

        # If we are in the first (C->S) post
        if 'I' in post_data and 'A' in post_data:

            # Get the I and A sent by the client
            I = post_data.get('I')
            A = post_data.get('A')

            # Find from the database the password of the client and compute v from it
            P = passwords[I]
            v = modular_pow(g, h(salt + P), N)

            # Compute B and u
            B = (k * v + modular_pow(g, b, N)) % N
            u = h(str(A) + str(B))

            # Compute S and K
            S = modular_pow(A * modular_pow(v, u, N), b, N)
            K = sha256(str(S).encode()).digest()

            # Send the user the salt and B (first S->C)
            return jsonify(salt=salt, B=B)

        # If we are in the second (C->S) post
        elif 'hm' in post_data:

            # Get the client HMAC
            hm = post_data.get('hm')

            # Compute the server HMAC
            my_hm = hmac_sha256(K, salt.encode())

            # Tell the user whether they match (second S->C)
            if hm == my_hm:
                return "OK", 200
            else:
                return "BAD", 500


def main():
    app.run()


if __name__ == '__main__':
    main()
