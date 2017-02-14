def pkcs7_pad(message, block_size):
    """Pads the given message with the PKCS 7 padding format for the given block size."""

    # If the length of the given message is already equal to the block size, there is no need to pad
    if len(message) == block_size:
        return message

    # Otherwise compute the padding byte and return the padded message
    ch = block_size - len(message) % block_size
    return message + bytes([ch] * ch)


def is_pkcs7_padded(binary_data):
    """Returns whether the data is PKCS 7 padded."""

    # Take what we expect to be the padding
    padding = binary_data[-binary_data[-1]:]

    # Check that all the bytes in the range indicated by the padding are equal to the padding value itself
    return all(padding[b] == len(padding) for b in range(0, len(padding)))


def pkcs7_unpad(data):
    """Unpads the given data from its PKCS 7 padding and returns it."""
    if len(data) == 0:
        raise Exception("The input data must contain at least one byte")

    if not is_pkcs7_padded(data):
        return data

    padding_len = data[len(data) - 1]
    return data[:-padding_len]


def main():
    message = b"YELLOW SUBMARINE"
    b = pkcs7_pad(message, 20)

    # Check that the padding and unpadding methods work properly
    assert pkcs7_unpad(b) == message


if __name__ == "__main__":
    main()
