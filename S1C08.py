from Crypto.Cipher.AES import block_size


def count_aes_ecb_repetitions(ciphertext):
    """Counts the number of repeated chunks of the ciphertext and returns it."""
    chunks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    number_of_duplicates = len(chunks) - len(set(chunks))
    return number_of_duplicates


def detect_ecb_encrypted_ciphertext(ciphertexts):
    """Detects which ciphertext among the given one is the one most likely encrypted with AES in ECB mode."""
    best = (-1, 0)     # index of best candidate, repetitions of best candidate

    # For each ciphertext
    for i in range(len(ciphertexts)):

        # Count the block repetitions
        repetitions = count_aes_ecb_repetitions(ciphertexts[i])

        # Keep the ciphertext with most repetitions
        best = max(best, (i, repetitions), key=lambda t: t[1])

    # Return the ciphertext with most repetitions
    return best


def main():
    ciphertexts = [bytes.fromhex(line.strip()) for line in open("S1C08_input.txt")]
    result = detect_ecb_encrypted_ciphertext(ciphertexts)

    # Compute and print the ciphertext which was encrypted with AES-ECB
    print("The ciphertext encrypted in ECB mode is the one at position", result[0],
          "which contains", result[1], "repetitions")

    # Check that the detection works correctly
    assert result[0] == 132


if __name__ == "__main__":
    main()
