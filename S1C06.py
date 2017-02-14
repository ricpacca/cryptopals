from base64 import b64decode
from S1C03 import singlechar_xor_brute_force, get_english_score
from S1C05 import repeating_key_xor
from itertools import combinations


def hamming_distance(binary_seq_1, binary_seq_2):
    """Computes the edit distance/Hamming distance between two equal-length strings."""
    assert len(binary_seq_1) == len(binary_seq_2)
    dist = 0

    for bit1, bit2 in zip(binary_seq_1, binary_seq_2):
        diff = bit1 ^ bit2
        dist += sum([1 for bit in bin(diff) if bit == '1'])

    return dist


def break_repeating_key_xor(binary_data):
    """Breaks the repeating key XOR encryption statistically."""
    normalized_distances = {}

    # For each key_size (from the suggested range)
    for key_size in range(2, 41):

        # Take the first four key_size worth of bytes (as suggested as an option)
        chunks = [binary_data[i:i + key_size] for i in range(0, len(binary_data), key_size)][:4]

        # Sum the hamming distances between each pair of chunks
        distance = 0
        pairs = combinations(chunks, 2)
        for (x, y) in pairs:
            distance += hamming_distance(x, y)

        # And compute the average distance
        distance /= 6

        # Normalize the result by dividing by key_size
        normalized_distance = distance / key_size

        # Store the normalized distance for the given key_size
        normalized_distances[key_size] = normalized_distance

    # The key_sizes with the smallest normalized edit distances are the most likely ones
    possible_key_sizes = sorted(normalized_distances, key=normalized_distances.get)[:3]
    possible_plaintexts = []

    # Now we can try which one is really the correct one among the top 3 most likely key_sizes
    for d in possible_key_sizes:
        key = b''

        # Break the ciphertext into blocks of key_size length
        for i in range(d):
            block = b''

            # Transpose the blocks: make a block that is the i-th byte of every block
            for j in range(i, len(binary_data), d):
                block += bytes([binary_data[j]])

            # Solve each block as if it was single-character XOR
            key += bytes([singlechar_xor_brute_force(block)['key']])

        # Store the candidate plaintext that we would get with the key that we just found
        possible_plaintexts.append((repeating_key_xor(binary_data, key), key))

    # Return the candidate with the highest English score
    return max(possible_plaintexts, key=lambda k: get_english_score(k[0]))


def main():

    # Check that the hamming distance function works properly
    assert hamming_distance(b'this is a test', b'wokka wokka!!!') == 37

    with open("S1C06_input.txt") as input_file:
        data = b64decode(input_file.read())

    # Compute and print the result of the attack
    result = break_repeating_key_xor(data)
    print("Key =", result[1].decode())
    print("---------------------------------------")
    print(result[0].decode().rstrip())


if __name__ == "__main__":
    main()
