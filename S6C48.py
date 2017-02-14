from S6C47 import ceil, RSAPaddingOracle, pkcs_1_5_padding_oracle_attack, pkcs_1_5_pad


def main():
    """This challenge uses the same code of the S6C47 one.
    I coded the full Bleichenbacher's algorithm directly there.
    It just takes a little bit more time to run.
    """

    key_bit_length = 768
    key_byte_length = ceil(key_bit_length, 8)

    rsa_padding_oracle = RSAPaddingOracle(key_bit_length)

    # Pad a short message m and encrypt it to get c
    data_block = b'kick it, CC'
    m = pkcs_1_5_pad(data_block, key_byte_length)

    c = rsa_padding_oracle.encrypt(m)

    # Check that the rsa padding oracle decrypts the c correctly
    assert rsa_padding_oracle.is_padding_correct(c)

    # Test that the attack works
    hacked_message = pkcs_1_5_padding_oracle_attack(c, rsa_padding_oracle, key_byte_length)
    assert m == hacked_message


if __name__ == '__main__':
    main()
