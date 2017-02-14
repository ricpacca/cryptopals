from S2C10 import aes_cbc_encrypt, aes_cbc_decrypt
from S4C28 import sha1
from Crypto import Random
from Crypto.Cipher import AES
from S5C33 import DiffieHellman
from binascii import unhexlify

# TODO Implement the network part, which is now simulated


def parameter_injection_attack(alice, bob):
    """Simulates a MITM key-fixing attack on Diffie-Hellman with parameter injection."""

    # Step 1: Alice computes A and sends it to the MITM (thinking of Bob)
    A = alice.get_public_key()

    # Step 2: the MITM changes A with p and sends it to Bob
    A = alice.p

    # Step 3: Bob computes B and sends it to the MITM (thinking of Alice)
    B = bob.get_public_key()

    # Step 4: the MITM changes B with p and sends it to Alice
    B = bob.p

    # Step 5: Alice finally sends her encrypted message to Bob (without knowledge of MITM)
    _msg = b'Hello, how are you?'
    _a_key = unhexlify(sha1(str(alice.get_shared_secret_key(B)).encode()))[:16]
    _a_iv = Random.new().read(AES.block_size)
    a_question = aes_cbc_encrypt(_msg, _a_key, _a_iv) + _a_iv

    # Step 6: the MITM relays that to Bob

    # Step 7: Bob decrypts the message sent by Alice (without knowing of the attack), encrypts it and sends it again
    _b_key = unhexlify(sha1(str(bob.get_shared_secret_key(A)).encode()))[:16]
    _a_iv = a_question[-AES.block_size:]
    _a_message = aes_cbc_decrypt(a_question[:-AES.block_size], _b_key, _a_iv)
    _b_iv = Random.new().read(AES.block_size)
    b_answer = aes_cbc_encrypt(_a_message, _b_key, _b_iv) + _b_iv

    # Step 8: the MITM relays that to Alice

    # Step 9: the MITM decrypts the message (either from a_question or from b_answer, it's the same).
    #
    # Finding the key after replacing A and B with p is, in fact, very easy.
    # Instead of (B^a % p) or (A^b % p), the shared secret key of the exercise became (p^a % p)
    # and (p^b % p), both equal to zero!
    mitm_hacked_key = unhexlify(sha1(b'0').encode())[:16]

    # Hack Alice's question
    mitm_a_iv = a_question[-AES.block_size:]
    mitm_hacked_message_a = aes_cbc_decrypt(a_question[:-AES.block_size], mitm_hacked_key, mitm_a_iv)

    # Hack Bob's answer (which here is the same)
    mitm_b_iv = b_answer[-AES.block_size:]
    mitm_hacked_message_b = aes_cbc_decrypt(b_answer[:-AES.block_size], mitm_hacked_key, mitm_b_iv)

    # Check if the attack worked
    assert _msg == mitm_hacked_message_a == mitm_hacked_message_b


def main():
    alice = DiffieHellman()
    bob = DiffieHellman()
    parameter_injection_attack(alice, bob)


if __name__ == '__main__':
    main()
