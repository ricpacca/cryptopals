from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64decode
from S3C18 import aes_ctr
from S3C19 import crack_ctr_same_nonce


def main():
    """I actually used the suggested "statistic" approach to solve S3C19, so I will reuse the same code here."""
    original_plaintexts = []
    ciphertexts = []
    random_key = Random.new().read(AES.key_size[0])

    with open("S3C20_input.txt") as f:
        for line in f:
            original_plaintext = b64decode(line)
            original_plaintexts.append(original_plaintext)
            ciphertexts.append(aes_ctr(original_plaintext, random_key, 0))

    cracked_plaintexts = crack_ctr_same_nonce(ciphertexts)

    # Print each cracked plaintext. Some of them will be slightly different from the original plaintext
    # but the attack is not perfect and as long as they are similar I would say that it worked.
    for plaintext, original in zip(cracked_plaintexts, original_plaintexts):
        print(plaintext)
        # print(original)   # Check if the cracked plaintext matches the original plaintext


if __name__ == '__main__':
    main()
