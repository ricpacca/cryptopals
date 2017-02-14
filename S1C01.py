from enum import Enum

b64_encoding_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk" \
                     "lmnopqrstuvwxyz0123456789+/"


class Status(Enum):
    """Represents the possible status of the converter
    upon finishing to read a hex character of 4 bits.
    """
    START_NEW = 0
    TAKE_2 = 1
    TAKE_4 = 2


def hex_to_base64(hexdata):
    """Returns a Base64 encoding of the given Hexadecimal string."""
    b64data = ""                # Encoding which will be returned

    sixbits = 0                 # Group of six bits that are being encoded
    status = Status.START_NEW   # Status of the conversion

    for hexchar in hexdata:
        dec = int(hexchar, 16)   # Decimal value of the character

        # If a new group of six has to be considered,
        # take all the 4 bits of the current hex characters
        # and save in the status that we still need 2 bits.
        if status == Status.START_NEW:
            sixbits = dec
            status = Status.TAKE_2

        # If only 2 bits need to be considered, append them to
        # the current group of six bits. The group, now complete,
        # is then encoded and added to the encoded string.
        # The next 2 bits are added to a new group and the status
        # is set to say that we still need 4 bits.
        elif status == Status.TAKE_2:
            sixbits = (sixbits << 2) | (dec >> 2)
            b64data += b64_encoding_table[sixbits]
            sixbits = (dec & 0x3)   # 0x3 is 0011
            status = Status.TAKE_4

        # If only 4 bits need to be considered, append them to
        # the current group of six bits. The group, now complete,
        # is then encoded and added to the encoded string.
        # The status is set to say that we can start with a new group.
        elif status == Status.TAKE_4:
            sixbits = (sixbits << 4) | dec
            b64data += b64_encoding_table[sixbits]
            status = Status.START_NEW

    # If there are still 2 bits missing to the current group of six bits
    # encode the last character by appending two 0s to it.
    # Then add "=" to the encoding.
    if status == Status.TAKE_2:
        sixbits <<= 2
        b64data += b64_encoding_table[sixbits]
        b64data += "="

    # If there are still 4 bits missing to the current group of six bits
    # encode the last character by appending four 0s to it.
    # Then add "==" to the encoding.
    elif status == Status.TAKE_4:
        sixbits <<= 4
        b64data += b64_encoding_table[sixbits]
        b64data += "=="

    return b64data


def main():
    # Check that the method works properly
    assert hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b"
                         "65206120706f69736f6e6f7573206d757368726f6f6d") ==\
           "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"


if __name__ == '__main__':
    main()
