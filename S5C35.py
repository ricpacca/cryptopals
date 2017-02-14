from S2C09 import is_pkcs7_padded, pkcs7_unpad
from S2C10 import aes_cbc_encrypt, aes_cbc_decrypt
from S4C28 import sha1
from Crypto import Random
from Crypto.Cipher import AES
from S5C33 import DiffieHellman
from binascii import unhexlify

# TODO Implement the network part, which is now simulated


def malicious_g_attack():
    """Simulates the break of Diffie-Hellman with negotiated groups by using malicious 'g' parameters."""
    p = DiffieHellman.DEFAULT_P

    for g in [1, p, p - 1]:

        # Step 1: the MITM changes the default g sent by Alice to Bob with a forced value
        alice = DiffieHellman()
        bob = DiffieHellman(g=g)

        # Step 2: Bob receives this forced g and sends an ACK to Alice

        # Step 3: Alice computes A and sends it to the MITM (thinking of Bob)
        A = alice.get_public_key()

        # Step 4: Bob computes B and sends it to the MITM (thinking of Alice)
        B = bob.get_public_key()

        # Step 5: Alice sends her encrypted message to Bob (without knowledge of MITM)
        _msg = b'Hello, how are you?'
        _a_key = unhexlify(sha1(str(alice.get_shared_secret_key(B)).encode()))[:16]
        _a_iv = Random.new().read(AES.block_size)
        a_question = aes_cbc_encrypt(_msg, _a_key, _a_iv) + _a_iv

        # Step 6: Bob receives the message sent by Alice (without knowing of the attack)
        # However, this time Bob will not be able to decrypt it, because (if I understood the
        # challenge task correctly) Alice and Bob now use different values of g.

        # Step 7: the MITM decrypts the Alice's question
        mitm_a_iv = a_question[-AES.block_size:]

        # When g is 1, the secret key is also 1
        if g == 1:
            mitm_hacked_key = unhexlify(sha1(b'1').encode())[:16]
            mitm_hacked_message = aes_cbc_decrypt(a_question[:-AES.block_size], mitm_hacked_key, mitm_a_iv)

        # When g is equal to p, it works the same as in the S5C34 attack (the secret key is 0)
        elif g == p:
            mitm_hacked_key = unhexlify(sha1(b'0').encode())[:16]
            mitm_hacked_message = aes_cbc_decrypt(a_question[:-AES.block_size], mitm_hacked_key, mitm_a_iv)

        # When g is equal to p - 1, the secret key is (-1)^(ab), which is either (+1 % p) or (-1 % p).
        # We can try both and later check the padding to see which one is correct.
        else:

            for candidate in [str(1).encode(), str(p - 1).encode()]:
                mitm_hacked_key = unhexlify(sha1(candidate).encode())[:16]
                mitm_hacked_message = aes_cbc_decrypt(a_question[:-AES.block_size], mitm_hacked_key,
                                                      mitm_a_iv, unpad=False)

                if is_pkcs7_padded(mitm_hacked_message):
                    mitm_hacked_message = pkcs7_unpad(mitm_hacked_message)
                    break

        # Check if the attack worked
        assert _msg == mitm_hacked_message


def main():
    malicious_g_attack()


if __name__ == '__main__':
    main()
