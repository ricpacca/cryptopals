from S1C03 import singlechar_xor_brute_force, pretty_print_result


def detect_encrypted_text(encrypted_strings):
    """Performs a singlechar XOR brute force attack to every ciphertext of the input, gets a plaintext
    from each of the ciphertexts and returns the decrypted plaintext which has the highest English score.
    """
    candidates = []

    for string in encrypted_strings:
        candidates.append(singlechar_xor_brute_force(string))

    # Return the candidate with the highest English score
    return sorted(candidates, key=lambda c: c['score'], reverse=True)[0]


def main():
    ciphertexts = [bytes.fromhex(line.strip()) for line in open("S1C04_input.txt")]
    most_likely_plaintext = detect_encrypted_text(ciphertexts)
    pretty_print_result(most_likely_plaintext)

    # Check that the attack works properly
    assert most_likely_plaintext['plaintext'].rstrip() == b"Now that the party is jumping"

if __name__ == "__main__":
    main()
