# http://www.data-compression.com/english.html
CHARACTER_FREQ = {
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610,
    'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513,
    'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
    'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182
}


def get_english_score(input_bytes):
    """Returns a score which is the sum of the probabilities in how each letter of the input data
    appears in the English language. Uses the above probabilities.
    """
    score = 0

    for byte in input_bytes:
        score += CHARACTER_FREQ.get(chr(byte).lower(), 0)

    return score


def singlechar_xor(input_bytes, key_value):
    """XORs every byte of the input with the given key_value and returns the result."""
    output = b''

    for char in input_bytes:
        output += bytes([char ^ key_value])

    return output


def singlechar_xor_brute_force(ciphertext):
    """Tries every possible byte for the single-char key, decrypts the ciphertext with that byte
    and computes the english score for each plaintext. The plaintext with the highest score
    is likely to be the one decrypted with the correct value of key.
    """
    candidates = []

    for key_candidate in range(256):
        plaintext_candidate = singlechar_xor(ciphertext, key_candidate)
        candidate_score = get_english_score(plaintext_candidate)

        result = {
            'key': key_candidate,
            'score': candidate_score,
            'plaintext': plaintext_candidate
        }

        candidates.append(result)

    # Return the candidate with the highest English score
    return sorted(candidates, key=lambda c: c['score'], reverse=True)[0]


def pretty_print_result(result):
    """Prints the given resulting candidate in a pretty format."""
    print(result['plaintext'].decode().rstrip(), "\tScore:", "{0:.2f}".format(result['score']),
          "\tKey:", chr(result['key']))


def main():
    ciphertext = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    most_likely_plaintext = singlechar_xor_brute_force(ciphertext)
    pretty_print_result(most_likely_plaintext)

    # Check that the attack works properly
    assert most_likely_plaintext['plaintext'].rstrip() == b"Cooking MC's like a pound of bacon"


if __name__ == "__main__":
    main()
