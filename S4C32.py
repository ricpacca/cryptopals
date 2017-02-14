from S4C31 import discover_mac_with_timing_attack


def main():
    """Solved the same way as challenge 31.
    To play between the two challenge, you can try to change the rounds value in the discover_mac function call
    and the delay value in the server module.

    NOTE: Make sure that the web server S4C31_server is running.
    """

    # Correct HMAC for foo: 8c80a95a8e72b3e822a13924553351a433e267d8
    discover_mac_with_timing_attack("foo", 10)


if __name__ == '__main__':
    main()
