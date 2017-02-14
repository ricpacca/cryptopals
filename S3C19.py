from S1C03 import get_english_score, singlechar_xor
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64decode
from S3C18 import aes_ctr
from S2C10 import xor_data


def get_keystream_byte(data):
    """Finds the most probable byte to which the input data was XORed, using the
    frequencies of English letters as metric.
    """
    best_candidate, score = 0, 0

    # Try all possible bytes
    for key_candidate in range(256):

        # Get the score of the current byte
        curr_score = get_english_score(singlechar_xor(data, key_candidate))

        # And keep the byte with the highest score as best candidate
        if curr_score > score:
            score = curr_score
            best_candidate = key_candidate

    return bytes([best_candidate])


def crack_ctr_same_nonce(ciphertexts):
    """Attempt to automate the process of cracking AES-CTR when the same nonce is used repeatedly.
    The approach is to take all the bytes that were encrypted with the same byte of the keystream
    and use the singlechar_xor crypto hack that we used before to find each byte of the key.
    """
    keystream = b''

    # Take the i-th character of each ciphertext to form a column of bytes that were XORed against the same byte
    for i in range(max(map(len, ciphertexts))):
        column = b''
        for c in ciphertexts:
            column += bytes([c[i]]) if i < len(c) else b''

        # Get the most likely character that was used for the XOR
        keystream += get_keystream_byte(column)

    # Once we got the keystream, get we can easily get all the plaintexts
    plaintexts = []
    for c in ciphertexts:
        plaintexts.append(xor_data(c, keystream))

    return plaintexts


def main():
    """NOTE:
    After writing this code I realized that the approach I was using was the S3C20 solution.

    To solve this problem with a manual approach there are other ways. For example, we could start
    by considering, for each position, the key (byte) which creates the most spaces (since the spaces
    are very frequent), and then find patterns manually by guesses.

    I like to use a Jupyter notebook for manually playing with these kind of challenges where
    automating the steps is difficult and there has to be human intervention.
    Maybe I will add a manual solution to this challenge at some point.
    """

    original_plaintexts = []
    ciphertexts = []
    random_key = Random.new().read(AES.key_size[0])

    with open("S3C19_input.txt") as f:
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
