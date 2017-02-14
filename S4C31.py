from binascii import hexlify
from statistics import median
import requests

# The attacker knows that the HMAC is 20 bytes long
HMAC_LEN = 20


def get_next_byte(known_bytes, filename, rounds):
    """Guesses the next byte of the HMAC for the given filename by performing a timing attack.
    The guess is done by making an average of the time taken by $rounds requests to the web-server.
    Because we guess that we web-server is using the insecure_compare function, we can guess that
    the requests that take the longest to be done are the ones with the correct byte.
    """

    # Count the number of zeros to add to our padding
    suffix_len = HMAC_LEN - len(known_bytes)

    # Initialize array counting the request times for every possible byte
    times = [[] for _ in range(256)]

    # For each byte, perform $rounds requests, so that we can have a better
    # statistical evidence of what requests take longer.
    for _ in range(rounds):

        # Try all possible bytes
        for i in range(256):
            suffix = bytes([i]) + (b'\x00' * (suffix_len - 1))
            signature = hexlify(known_bytes + suffix).decode()

            response = requests.get('http://localhost:8082/test?file=' + filename + '&signature=' + signature)

            # Just in case we found the correct signature already, return what we discovered
            if response.status_code == 200:
                return suffix

            times[i].append(response.elapsed.total_seconds())

    # Take the median of the requests times for each byte
    median_times = [median(byte_times) for byte_times in times]

    # Get the index of the item which took the highest median time for the requests
    best = max(range(256), key=lambda b: median_times[b])

    return bytes([best])


def discover_mac_with_timing_attack(filename, rounds):
    """Performs a timing attack on the HMAC server."""
    print("Timing attack started.")

    # Get the HMAC byte by byte
    known_bytes = b''
    while len(known_bytes) < HMAC_LEN:
        known_bytes += get_next_byte(known_bytes, filename, rounds)

        signature = hexlify(known_bytes).decode()
        print("Discovered so far:", signature)

    # Check if the HMAC we found is correct
    response = requests.get('http://localhost:8082/test?file=' + filename + '&signature=' + signature)

    if response.status_code == 200:
        print("\n> We made it! The HMAC is:", signature)
    else:
        print("\n> Unfortunately the attack did not work.")


def main():
    """Make sure that the web server S4C31_server is running.
    NOTE: This attack takes hours to finish.
    """

    # Correct HMAC for foo: 8c80a95a8e72b3e822a13924553351a433e267d8
    discover_mac_with_timing_attack("foo", 10)


if __name__ == '__main__':
    main()
